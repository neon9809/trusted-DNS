// Package rewriter implements DNS response rewriting, including
// A/AAAA record reordering based on probe results. It preserves
// DNS semantics: no fabricated answers, no question modification,
// and TTL preservation with optional minimum floor.
package rewriter

import (
	"context"
	"encoding/binary"
	"log"
	"net"

	"github.com/neon9809/trusted-dns/docker/internal/probe"
)

// Config holds rewriter configuration.
type Config struct {
	Enabled     bool
	MinTTL      uint32 // minimum TTL floor in seconds
	SingleAddr  bool   // if true, return only the best address
}

// DefaultConfig returns the default rewriter configuration.
func DefaultConfig() Config {
	return Config{
		Enabled:    true,
		MinTTL:     60,
		SingleAddr: false,
	}
}

// Rewriter modifies DNS responses based on probe results.
type Rewriter struct {
	config Config
	probe  *probe.Engine
}

// New creates a new Rewriter.
func New(config Config, probeEngine *probe.Engine) *Rewriter {
	return &Rewriter{
		config: config,
		probe:  probeEngine,
	}
}

// Rewrite processes a DNS response, optionally probing and reordering
// A/AAAA records. The original DNS ID and Question are preserved.
func (r *Rewriter) Rewrite(ctx context.Context, originalQuery, response []byte) []byte {
	if !r.config.Enabled || r.probe == nil || !r.probe.Enabled() {
		return r.preserveID(originalQuery, response)
	}

	// Ensure the DNS ID matches the original query
	response = r.preserveID(originalQuery, response)

	// Parse the response to find A/AAAA records
	ips, recordType := r.extractAddresses(response)
	if len(ips) <= 1 {
		return response // nothing to reorder
	}

	// Probe addresses
	results := r.probe.ProbeAddresses(ctx, ips)

	// Reorder the response
	reordered := r.reorderResponse(response, results, recordType)
	if reordered != nil {
		return reordered
	}

	return response
}

// preserveID ensures the DNS response ID matches the original query ID.
func (r *Rewriter) preserveID(query, response []byte) []byte {
	if len(query) >= 2 && len(response) >= 2 {
		response[0] = query[0]
		response[1] = query[1]
	}
	return response
}

// extractAddresses parses A/AAAA records from a DNS response.
func (r *Rewriter) extractAddresses(response []byte) ([]net.IP, uint16) {
	if len(response) < 12 {
		return nil, 0
	}

	// Get answer count
	anCount := binary.BigEndian.Uint16(response[6:8])
	if anCount == 0 {
		return nil, 0
	}

	// Skip header (12 bytes) and question section
	off := 12
	qdCount := binary.BigEndian.Uint16(response[4:6])
	for i := 0; i < int(qdCount); i++ {
		off = skipName(response, off)
		off += 4 // QTYPE + QCLASS
	}

	var ips []net.IP
	var recordType uint16

	for i := 0; i < int(anCount) && off < len(response); i++ {
		off = skipName(response, off)
		if off+10 > len(response) {
			break
		}

		rtype := binary.BigEndian.Uint16(response[off:])
		// rclass := binary.BigEndian.Uint16(response[off+2:])
		// ttl := binary.BigEndian.Uint32(response[off+4:])
		rdlen := binary.BigEndian.Uint16(response[off+8:])
		off += 10

		if off+int(rdlen) > len(response) {
			break
		}

		if rtype == 1 && rdlen == 4 { // A record
			ip := net.IP(make([]byte, 4))
			copy(ip, response[off:off+4])
			ips = append(ips, ip)
			recordType = 1
		} else if rtype == 28 && rdlen == 16 { // AAAA record
			ip := net.IP(make([]byte, 16))
			copy(ip, response[off:off+16])
			ips = append(ips, ip)
			recordType = 28
		}

		off += int(rdlen)
	}

	return ips, recordType
}

// reorderResponse reorders A/AAAA records in the DNS response based on probe results.
func (r *Rewriter) reorderResponse(response []byte, results []probe.Result, recordType uint16) []byte {
	if len(results) == 0 {
		return nil
	}

	// For simplicity, we rebuild the answer section with reordered IPs.
	// This is a simplified approach that works for most common cases.
	if len(response) < 12 {
		return nil
	}

	anCount := binary.BigEndian.Uint16(response[6:8])
	if anCount == 0 {
		return nil
	}

	// Find the start of the answer section
	off := 12
	qdCount := binary.BigEndian.Uint16(response[4:6])
	for i := 0; i < int(qdCount); i++ {
		off = skipName(response, off)
		off += 4
	}
	answerStart := off

	// Collect answer records
	type answerRecord struct {
		start int
		end   int
		ip    net.IP
	}

	var records []answerRecord
	for i := 0; i < int(anCount) && off < len(response); i++ {
		recStart := off
		off = skipName(response, off)
		if off+10 > len(response) {
			break
		}

		rtype := binary.BigEndian.Uint16(response[off:])
		rdlen := binary.BigEndian.Uint16(response[off+8:])
		off += 10

		if off+int(rdlen) > len(response) {
			break
		}

		var ip net.IP
		if rtype == recordType {
			if rtype == 1 && rdlen == 4 {
				ip = net.IP(make([]byte, 4))
				copy(ip, response[off:off+4])
			} else if rtype == 28 && rdlen == 16 {
				ip = net.IP(make([]byte, 16))
				copy(ip, response[off:off+16])
			}
		}

		off += int(rdlen)
		records = append(records, answerRecord{start: recStart, end: off, ip: ip})
	}
	answerEnd := off

	if len(records) <= 1 {
		return nil
	}

	// Build IP to rank mapping from probe results
	ipRank := make(map[string]int)
	for i, r := range results {
		ipRank[r.IP.String()] = i
	}

	// Sort records by probe rank (records without matching IPs keep original order)
	type rankedRecord struct {
		data []byte
		rank int
	}

	ranked := make([]rankedRecord, len(records))
	for i, rec := range records {
		data := make([]byte, rec.end-rec.start)
		copy(data, response[rec.start:rec.end])

		rank := len(results) + i // default: after all probed results
		if rec.ip != nil {
			if r, ok := ipRank[rec.ip.String()]; ok {
				rank = r
			}
		}
		ranked[i] = rankedRecord{data: data, rank: rank}
	}

	// Sort by rank
	for i := 0; i < len(ranked)-1; i++ {
		for j := i + 1; j < len(ranked); j++ {
			if ranked[j].rank < ranked[i].rank {
				ranked[i], ranked[j] = ranked[j], ranked[i]
			}
		}
	}

	// Rebuild response
	result := make([]byte, 0, len(response))
	result = append(result, response[:answerStart]...)
	for _, rec := range ranked {
		result = append(result, rec.data...)
	}
	result = append(result, response[answerEnd:]...)

	// Apply minimum TTL floor
	if r.config.MinTTL > 0 {
		r.applyMinTTL(result, r.config.MinTTL)
	}

	log.Printf("[rewriter] reordered %d records", len(ranked))

	return result
}

// applyMinTTL ensures all answer TTLs are at least minTTL.
func (r *Rewriter) applyMinTTL(response []byte, minTTL uint32) {
	if len(response) < 12 {
		return
	}

	anCount := binary.BigEndian.Uint16(response[6:8])
	off := 12

	// Skip questions
	qdCount := binary.BigEndian.Uint16(response[4:6])
	for i := 0; i < int(qdCount); i++ {
		off = skipName(response, off)
		off += 4
	}

	// Process answers
	for i := 0; i < int(anCount) && off < len(response); i++ {
		off = skipName(response, off)
		if off+10 > len(response) {
			break
		}

		ttl := binary.BigEndian.Uint32(response[off+4:])
		if ttl < minTTL {
			binary.BigEndian.PutUint32(response[off+4:], minTTL)
		}

		rdlen := binary.BigEndian.Uint16(response[off+8:])
		off += 10 + int(rdlen)
	}
}

// skipName skips a DNS name (handles compression pointers).
func skipName(data []byte, off int) int {
	for off < len(data) {
		length := int(data[off])
		if length == 0 {
			return off + 1
		}
		if length&0xC0 == 0xC0 {
			// Compression pointer
			return off + 2
		}
		off += 1 + length
	}
	return off
}
