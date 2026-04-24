// Package transport implements the secure HTTPS transport between
// Docker and Worker, handling binary protocol encoding/decoding,
// encryption/decryption, and HTTP communication.
package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/neon9809/trusted-dns/docker/internal/protocol"
	"github.com/neon9809/trusted-dns/docker/internal/session"
)

// Transport handles communication with the Worker.
type Transport struct {
	workerURL    string
	protocolPath string
	httpClient   *http.Client
	session      *session.Manager
	keys         *protocol.DerivedKeys
}

// New creates a new Transport.
func New(workerURL string, protocolPath string, sess *session.Manager, keys *protocol.DerivedKeys) *Transport {
	if protocolPath == "" {
		protocolPath = "/dns-query"
	}
	return &Transport{
		workerURL:    workerURL,
		protocolPath: protocolPath,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		session: sess,
		keys:    keys,
	}
}

// Bootstrap performs the initial bootstrap handshake with the Worker.
func (t *Transport) Bootstrap(ctx context.Context) (*protocol.KeyBundle, error) {
	log.Println("[transport] starting bootstrap...")

	// Retry logic for bootstrap: up to 5 attempts with backoff
	const maxRetries = 5
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			backoffDur := time.Duration(1<<uint(attempt)) * time.Second
			log.Printf("[transport] bootstrap retry attempt %d after %v backoff", attempt, backoffDur)
			select {
			case <-time.After(backoffDur):
			case <-ctx.Done():
				return nil, fmt.Errorf("bootstrap context cancelled: %w", ctx.Err())
			}
		}

		// Generate boot nonce
		bootNonce, err := protocol.RandomBytes(protocol.BootNonceSize)
		if err != nil {
			lastErr = fmt.Errorf("gen boot nonce: %w", err)
			continue
		}

		timestampMs := uint64(time.Now().UnixMilli())

		// Compute bootstrap proof
		proof := protocol.ComputeBootstrapProof(t.keys.BootstrapKey, bootNonce, timestampMs)

		// Build payload: boot_nonce(16) + timestamp_ms(8) + bootstrap_proof(16) + capabilities(4)
		payload := make([]byte, 16+8+16+4)
		copy(payload[0:16], bootNonce)
		binary.BigEndian.PutUint64(payload[16:24], timestampMs)
		copy(payload[24:40], proof)
		binary.BigEndian.PutUint32(payload[40:44], 0x03) // capabilities: ICMP + TCP probe

		// Build header
		prefix := t.session.GetClientIDPrefix()
		header := &protocol.Header{
			Ver:            protocol.ProtocolVersion,
			MsgType:        protocol.MsgBootstrapReq,
			Flags:          0,
			ClientIDPrefix: prefix,
			BundleGen:      0,
			TicketID:       0,
			Seq:            0,
			PayloadLen:     uint32(len(payload)),
			HeaderMAC:      0,
		}

		// Send request
		respData, err := t.sendRequest(ctx, header, payload)
		if err != nil {
			lastErr = fmt.Errorf("bootstrap request: %w", err)
			log.Printf("[transport] bootstrap attempt %d failed: %v", attempt+1, err)
			continue
		}

		// Parse response
		respHeader, err := protocol.DecodeHeader(respData)
		if err != nil {
			lastErr = fmt.Errorf("decode bootstrap resp header: %w", err)
			continue
		}

		if respHeader.MsgType == protocol.MsgErrorResp {
			errResp := protocol.ParseErrorResponse(respData[protocol.HeaderSize:])
			lastErr = fmt.Errorf("bootstrap error: %s", errResp.Error())
			continue
		}

		if respHeader.MsgType != protocol.MsgBootstrapResp {
			lastErr = fmt.Errorf("unexpected response type: 0x%02x", respHeader.MsgType)
			continue
		}

		respPayload := respData[protocol.HeaderSize : protocol.HeaderSize+respHeader.PayloadLen]

		// Parse: server_time_ms(8) + bundle_gen(8) + nonce(12) + ciphertext
		if len(respPayload) < 28 {
			lastErr = fmt.Errorf("bootstrap response payload too short")
			continue
		}

		bundleGen := binary.BigEndian.Uint64(respPayload[8:16])
		nonce := respPayload[16:28]
		ciphertext := respPayload[28:]

		// Build AAD for decryption (response header with correct fields)
		aadHeader := &protocol.Header{
			Ver:            protocol.ProtocolVersion,
			MsgType:        protocol.MsgBootstrapResp,
			Flags:          0,
			ClientIDPrefix: respHeader.ClientIDPrefix,
			BundleGen:      bundleGen,
			TicketID:       0,
			Seq:            0,
			PayloadLen:     0,
			HeaderMAC:      0,
		}
		aad := protocol.EncodeHeader(aadHeader)

		// Decrypt KeyBundle
		bundleBytes, err := protocol.AEADDecrypt(t.keys.BundleWrapKey, nonce, ciphertext, aad)
		if err != nil {
			lastErr = fmt.Errorf("decrypt key bundle: %w", err)
			continue
		}

		bundle, err := protocol.DeserializeKeyBundle(bundleBytes)
		if err != nil {
			lastErr = fmt.Errorf("deserialize key bundle: %w", err)
			continue
		}

		log.Printf("[transport] bootstrap success: gen=%d, tickets=%d",
			bundle.BundleGen, len(bundle.SessionTickets))

		return bundle, nil
	}

	return nil, fmt.Errorf("bootstrap failed after %d attempts: %w", maxRetries, lastErr)
}

// Query sends an encrypted DNS query through the Worker.
func (t *Transport) Query(ctx context.Context, dnsQuery []byte) ([]byte, error) {
	// Acquire a ticket
	ticketInfo, err := t.session.AcquireTicket()
	if err != nil {
		return nil, fmt.Errorf("acquire ticket: %w", err)
	}

	bundle := t.session.GetBundle()
	if bundle == nil {
		return nil, fmt.Errorf("no active bundle")
	}

	// Build header
	prefix := t.session.GetClientIDPrefix()
	header := &protocol.Header{
		Ver:            protocol.ProtocolVersion,
		MsgType:        protocol.MsgQueryReq,
		Flags:          0,
		ClientIDPrefix: prefix,
		BundleGen:      bundle.BundleGen,
		TicketID:       ticketInfo.Ticket.TicketID,
		Seq:            ticketInfo.Seq,
		PayloadLen:     0, // set later
		HeaderMAC:      0,
	}

	// Build AAD from header
	headerBytes := protocol.EncodeHeader(header)

	// Encrypt DNS query
	nonce, ciphertext, err := protocol.AEADEncrypt(
		ticketInfo.QueryKeys.ReqKey, dnsQuery, headerBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("encrypt dns query: %w", err)
	}

	// Build payload: ticket_blob(114) + nonce(12) + ciphertext
	ticketBlob := protocol.EncodeSessionTicket(ticketInfo.Ticket)
	payloadLen := len(ticketBlob) + len(nonce) + len(ciphertext)
	payload := make([]byte, payloadLen)
	off := 0
	copy(payload[off:], ticketBlob); off += len(ticketBlob)
	copy(payload[off:], nonce); off += len(nonce)
	copy(payload[off:], ciphertext)

	header.PayloadLen = uint32(payloadLen)

	// Retry logic for queries: up to 2 attempts
	const maxRetries = 2
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			log.Printf("[transport] query retry attempt %d", attempt)
			select {
			case <-time.After(500 * time.Millisecond):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		// Send request
		respData, err := t.sendRequest(ctx, header, payload)
		if err != nil {
			lastErr = err
			continue
		}

		// Parse response
		respHeader, err := protocol.DecodeHeader(respData)
		if err != nil {
			lastErr = err
			continue
		}

		if respHeader.MsgType == protocol.MsgErrorResp {
			errResp := protocol.ParseErrorResponse(respData[protocol.HeaderSize:])
			lastErr = fmt.Errorf("query error: %s", errResp.Error())
			continue
		}

		if respHeader.MsgType != protocol.MsgQueryResp {
			lastErr = fmt.Errorf("unexpected response type: 0x%02x", respHeader.MsgType)
			continue
		}

		respPayload := respData[protocol.HeaderSize : protocol.HeaderSize+respHeader.PayloadLen]

		// Parse: resolver_id(1) + transport_flags(1) + upstream_rtt_ms(2) + nonce(12) + ciphertext
		if len(respPayload) < 16 {
			lastErr = fmt.Errorf("query response payload too short")
			continue
		}

		respNonce := respPayload[4:16]
		respCiphertext := respPayload[16:]

		// Build AAD for decryption
		respAadHeader := &protocol.Header{
			Ver:            protocol.ProtocolVersion,
			MsgType:        protocol.MsgQueryResp,
			Flags:          0,
			ClientIDPrefix: respHeader.ClientIDPrefix,
			BundleGen:      respHeader.BundleGen,
			TicketID:       respHeader.TicketID,
			Seq:            respHeader.Seq,
			PayloadLen:     0,
			HeaderMAC:      0,
		}
		respAad := protocol.EncodeHeader(respAadHeader)

		// Decrypt DNS response
		dnsResp, err := protocol.AEADDecrypt(
			ticketInfo.QueryKeys.RespKey, respNonce, respCiphertext, respAad,
		)
		if err != nil {
			lastErr = err
			continue
		}

		return dnsResp, nil
	}

	return nil, fmt.Errorf("query failed after %d attempts: %w", maxRetries+1, lastErr)
}

// Refresh performs a bundle refresh with the Worker, with retry logic.
func (t *Transport) Refresh(ctx context.Context) (*protocol.KeyBundle, error) {
	log.Println("[transport] starting refresh...")

	bundle := t.session.GetBundle()
	if bundle == nil {
		return nil, fmt.Errorf("no active bundle for refresh")
	}

	refreshTicket := t.session.GetRefreshTicket()
	if refreshTicket == nil {
		return nil, fmt.Errorf("no refresh ticket available")
	}

	totalQueries := t.session.GetTotalQueries()

	// Compute refresh proof
	proof := protocol.ComputeRefreshProof(
		t.keys.RefreshAuthKey,
		refreshTicket.RefreshSeed[:],
		bundle.BundleGen,
		totalQueries,
	)

	// Build payload: refresh_ticket_blob(122) + spent_bundle_gen(8) +
	//   spent_query_count(4) + refresh_proof(32) + requested_reason(1)
	refreshBlob := protocol.EncodeRefreshTicket(refreshTicket)
	payloadLen := len(refreshBlob) + 8 + 4 + 32 + 1
	payload := make([]byte, payloadLen)
	off := 0
	copy(payload[off:], refreshBlob); off += len(refreshBlob)
	binary.BigEndian.PutUint64(payload[off:], bundle.BundleGen); off += 8
	binary.BigEndian.PutUint32(payload[off:], totalQueries); off += 4
	copy(payload[off:], proof); off += 32
	payload[off] = 0x00 // reason: budget exhausted

	// Build header
	prefix := t.session.GetClientIDPrefix()
	header := &protocol.Header{
		Ver:            protocol.ProtocolVersion,
		MsgType:        protocol.MsgRefreshReq,
		Flags:          0,
		ClientIDPrefix: prefix,
		BundleGen:      bundle.BundleGen,
		TicketID:       0,
		Seq:            0,
		PayloadLen:     uint32(payloadLen),
		HeaderMAC:      0,
	}

	// Retry logic: up to 3 attempts with exponential backoff
	const maxRetries = 3
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			backoffDur := time.Duration(1<<uint(attempt)) * time.Second
			log.Printf("[transport] refresh retry attempt %d after %v backoff", attempt, backoffDur)
			select {
			case <-time.After(backoffDur):
			case <-ctx.Done():
				return nil, fmt.Errorf("refresh context cancelled: %w", ctx.Err())
			}
		}

		// Send request
		respData, err := t.sendRequest(ctx, header, payload)
		if err != nil {
			lastErr = err
			log.Printf("[transport] refresh request attempt %d failed: %v", attempt+1, err)
			continue
		}

		// Parse response
		respHeader, err := protocol.DecodeHeader(respData)
		if err != nil {
			lastErr = err
			log.Printf("[transport] decode refresh resp attempt %d failed: %v", attempt+1, err)
			continue
		}

		if respHeader.MsgType == protocol.MsgErrorResp {
			errResp := protocol.ParseErrorResponse(respData[protocol.HeaderSize:])
			lastErr = fmt.Errorf("refresh error: %s", errResp.Error())
			log.Printf("[transport] refresh error response attempt %d: %v", attempt+1, lastErr)
			continue
		}

		if respHeader.MsgType != protocol.MsgRefreshResp {
			lastErr = fmt.Errorf("unexpected response type: 0x%02x", respHeader.MsgType)
			log.Printf("[transport] unexpected response attempt %d: %v", attempt+1, lastErr)
			continue
		}

		respPayload := respData[protocol.HeaderSize : protocol.HeaderSize+respHeader.PayloadLen]

		// Parse: server_time_ms(8) + bundle_gen(8) + nonce(12) + ciphertext
		if len(respPayload) < 28 {
			lastErr = fmt.Errorf("refresh response payload too short")
			log.Printf("[transport] short payload attempt %d: %v", attempt+1, lastErr)
			continue
		}

		nonce := respPayload[16:28]
		ciphertext := respPayload[28:]

		// Build AAD
		aadHeader := &protocol.Header{
			Ver:            protocol.ProtocolVersion,
			MsgType:        protocol.MsgRefreshResp,
			Flags:          0,
			ClientIDPrefix: respHeader.ClientIDPrefix,
			BundleGen:      respHeader.BundleGen,
			TicketID:       0,
			Seq:            0,
			PayloadLen:     0,
			HeaderMAC:      0,
		}
		aad := protocol.EncodeHeader(aadHeader)

		// Decrypt new KeyBundle
		bundleBytes, err := protocol.AEADDecrypt(t.keys.BundleWrapKey, nonce, ciphertext, aad)
		if err != nil {
			lastErr = err
			log.Printf("[transport] decrypt new bundle attempt %d failed: %v", attempt+1, err)
			continue
		}

		newBundle, err := protocol.DeserializeKeyBundle(bundleBytes)
		if err != nil {
			lastErr = err
			log.Printf("[transport] deserialize new bundle attempt %d failed: %v", attempt+1, err)
			continue
		}

		log.Printf("[transport] refresh success: new gen=%d", newBundle.BundleGen)
		return newBundle, nil
	}

	return nil, fmt.Errorf("refresh failed after %d attempts: %w", maxRetries, lastErr)
}

// sendRequest sends a binary protocol message to the Worker.
func (t *Transport) sendRequest(ctx context.Context, header *protocol.Header, payload []byte) ([]byte, error) {
	headerBytes := protocol.EncodeHeader(header)

	body := make([]byte, len(headerBytes)+len(payload))
	copy(body, headerBytes)
	copy(body[len(headerBytes):], payload)

	req, err := http.NewRequestWithContext(ctx, "POST", t.workerURL+t.protocolPath, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if len(respBody) < protocol.HeaderSize {
		return nil, fmt.Errorf("response too short: %d bytes", len(respBody))
	}

	return respBody, nil
}
