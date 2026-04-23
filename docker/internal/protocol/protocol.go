// Package protocol defines the Trusted-DNS binary protocol structures,
// message types, error codes, and serialization/deserialization routines.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Protocol version
const ProtocolVersion = 0x01

// Message types
const (
	MsgBootstrapReq  = 0x01
	MsgBootstrapResp = 0x02
	MsgQueryReq      = 0x03
	MsgQueryResp     = 0x04
	MsgRefreshReq    = 0x05
	MsgRefreshResp   = 0x06
	MsgErrorResp     = 0x7F
)

// Error codes
const (
	ErrBadVersion     = 0x01
	ErrBadType        = 0x02
	ErrBadTicket      = 0x03
	ErrExpired        = 0x04
	ErrOldGeneration  = 0x05
	ErrReplaySuspect  = 0x06
	ErrDecryptFailed  = 0x07
	ErrUpstreamFail   = 0x08
	ErrRateLimited    = 0x09
	ErrInternal       = 0x0A
)

// Fixed sizes
const (
	HeaderSize       = 32
	ClientIDSize     = 32
	ClientIDPrefix   = 8
	NonceSize        = 12
	TagSize          = 16
	TicketTagSize    = 16
	ResumeSeedSize   = 32
	RefreshSeedSize  = 32
	RefreshNonceSize = 16
	BootNonceSize    = 16
)

// Default policy values
const (
	DefaultTicketsPerBundle = 5
	DefaultQueriesPerTicket = 200
	DefaultQueriesPerBundle = 1000
	DefaultMaxClockSkewMs   = 300000
	DefaultAntiReplayWindow = 64
	DefaultTicketLifetimeMs = 3600000
)

// Header represents the 32-byte fixed protocol header.
type Header struct {
	Ver            uint8
	MsgType        uint8
	Flags          uint16
	ClientIDPrefix [8]byte
	BundleGen      uint64
	TicketID       uint16
	Seq            uint32
	PayloadLen     uint32
	HeaderMAC      uint16
}

// EncodeHeader serializes a Header to 32 bytes (big-endian).
func EncodeHeader(h *Header) []byte {
	buf := make([]byte, HeaderSize)
	buf[0] = h.Ver
	buf[1] = h.MsgType
	binary.BigEndian.PutUint16(buf[2:4], h.Flags)
	copy(buf[4:12], h.ClientIDPrefix[:])
	binary.BigEndian.PutUint64(buf[12:20], h.BundleGen)
	binary.BigEndian.PutUint16(buf[20:22], h.TicketID)
	binary.BigEndian.PutUint32(buf[22:26], h.Seq)
	binary.BigEndian.PutUint32(buf[26:30], h.PayloadLen)
	binary.BigEndian.PutUint16(buf[30:32], h.HeaderMAC)
	return buf
}

// DecodeHeader deserializes 32 bytes into a Header.
func DecodeHeader(data []byte) (*Header, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("header too short: %d < %d", len(data), HeaderSize)
	}
	h := &Header{
		Ver:     data[0],
		MsgType: data[1],
		Flags:   binary.BigEndian.Uint16(data[2:4]),
	}
	copy(h.ClientIDPrefix[:], data[4:12])
	h.BundleGen = binary.BigEndian.Uint64(data[12:20])
	h.TicketID = binary.BigEndian.Uint16(data[20:22])
	h.Seq = binary.BigEndian.Uint32(data[22:26])
	h.PayloadLen = binary.BigEndian.Uint32(data[26:30])
	h.HeaderMAC = binary.BigEndian.Uint16(data[30:32])
	return h, nil
}

// Policy holds the session policy parameters.
type Policy struct {
	TicketsPerBundle uint8
	QueriesPerTicket uint16
	QueriesPerBundle uint16
	MaxClockSkewMs   uint32
	AntiReplayWindow uint16
	TicketLifetimeMs uint64
}

// DefaultPolicy returns the default policy.
func DefaultPolicy() Policy {
	return Policy{
		TicketsPerBundle: DefaultTicketsPerBundle,
		QueriesPerTicket: DefaultQueriesPerTicket,
		QueriesPerBundle: DefaultQueriesPerBundle,
		MaxClockSkewMs:   DefaultMaxClockSkewMs,
		AntiReplayWindow: DefaultAntiReplayWindow,
		TicketLifetimeMs: DefaultTicketLifetimeMs,
	}
}

// SessionTicket represents a single session ticket.
const SessionTicketSize = 2 + 1 + 1 + 32 + 8 + 8 + 8 + 2 + 4 + 32 + 16 // = 114

type SessionTicket struct {
	TicketID    uint16
	Slot        uint8
	Reserved    uint8
	ClientID    [32]byte
	BundleGen   uint64
	NotBeforeMs uint64
	NotAfterMs  uint64
	QueryBudget uint16
	CounterBase uint32
	ResumeSeed  [32]byte
	TicketTag   [16]byte
}

// EncodeSessionTicket serializes a SessionTicket.
func EncodeSessionTicket(t *SessionTicket) []byte {
	buf := make([]byte, SessionTicketSize)
	off := 0
	binary.BigEndian.PutUint16(buf[off:], t.TicketID); off += 2
	buf[off] = t.Slot; off++
	buf[off] = t.Reserved; off++
	copy(buf[off:], t.ClientID[:]); off += 32
	binary.BigEndian.PutUint64(buf[off:], t.BundleGen); off += 8
	binary.BigEndian.PutUint64(buf[off:], t.NotBeforeMs); off += 8
	binary.BigEndian.PutUint64(buf[off:], t.NotAfterMs); off += 8
	binary.BigEndian.PutUint16(buf[off:], t.QueryBudget); off += 2
	binary.BigEndian.PutUint32(buf[off:], t.CounterBase); off += 4
	copy(buf[off:], t.ResumeSeed[:]); off += 32
	copy(buf[off:], t.TicketTag[:])
	return buf
}

// DecodeSessionTicket deserializes a SessionTicket.
func DecodeSessionTicket(data []byte) (*SessionTicket, error) {
	if len(data) < SessionTicketSize {
		return nil, fmt.Errorf("session ticket too short: %d", len(data))
	}
	t := &SessionTicket{}
	off := 0
	t.TicketID = binary.BigEndian.Uint16(data[off:]); off += 2
	t.Slot = data[off]; off++
	t.Reserved = data[off]; off++
	copy(t.ClientID[:], data[off:off+32]); off += 32
	t.BundleGen = binary.BigEndian.Uint64(data[off:]); off += 8
	t.NotBeforeMs = binary.BigEndian.Uint64(data[off:]); off += 8
	t.NotAfterMs = binary.BigEndian.Uint64(data[off:]); off += 8
	t.QueryBudget = binary.BigEndian.Uint16(data[off:]); off += 2
	t.CounterBase = binary.BigEndian.Uint32(data[off:]); off += 4
	copy(t.ResumeSeed[:], data[off:off+32]); off += 32
	copy(t.TicketTag[:], data[off:off+16])
	return t, nil
}

// RefreshTicket represents a refresh ticket.
const RefreshTicketSize = 32 + 8 + 8 + 8 + 2 + 16 + 32 + 16 // = 122

type RefreshTicket struct {
	ClientID           [32]byte
	BundleGen          uint64
	NotBeforeMs        uint64
	NotAfterMs         uint64
	RotateAfterQueries uint16
	RefreshNonce       [16]byte
	RefreshSeed        [32]byte
	RefreshTag         [16]byte
}

// EncodeRefreshTicket serializes a RefreshTicket.
func EncodeRefreshTicket(t *RefreshTicket) []byte {
	buf := make([]byte, RefreshTicketSize)
	off := 0
	copy(buf[off:], t.ClientID[:]); off += 32
	binary.BigEndian.PutUint64(buf[off:], t.BundleGen); off += 8
	binary.BigEndian.PutUint64(buf[off:], t.NotBeforeMs); off += 8
	binary.BigEndian.PutUint64(buf[off:], t.NotAfterMs); off += 8
	binary.BigEndian.PutUint16(buf[off:], t.RotateAfterQueries); off += 2
	copy(buf[off:], t.RefreshNonce[:]); off += 16
	copy(buf[off:], t.RefreshSeed[:]); off += 32
	copy(buf[off:], t.RefreshTag[:])
	return buf
}

// DecodeRefreshTicket deserializes a RefreshTicket.
func DecodeRefreshTicket(data []byte) (*RefreshTicket, error) {
	if len(data) < RefreshTicketSize {
		return nil, fmt.Errorf("refresh ticket too short: %d", len(data))
	}
	t := &RefreshTicket{}
	off := 0
	copy(t.ClientID[:], data[off:off+32]); off += 32
	t.BundleGen = binary.BigEndian.Uint64(data[off:]); off += 8
	t.NotBeforeMs = binary.BigEndian.Uint64(data[off:]); off += 8
	t.NotAfterMs = binary.BigEndian.Uint64(data[off:]); off += 8
	t.RotateAfterQueries = binary.BigEndian.Uint16(data[off:]); off += 2
	copy(t.RefreshNonce[:], data[off:off+16]); off += 16
	copy(t.RefreshSeed[:], data[off:off+32]); off += 32
	copy(t.RefreshTag[:], data[off:off+16])
	return t, nil
}

// KeyBundle holds the complete session material set.
type KeyBundle struct {
	BundleGen      uint64
	IssuedAtMs     uint64
	ExpireAtMs     uint64
	WorkerKID      uint16
	Policy         Policy
	SessionTickets []*SessionTicket
	RefreshTicket  *RefreshTicket
}

// ErrorResponse represents a protocol error.
type ErrorResponse struct {
	Code   uint8
	Detail string
}

func (e *ErrorResponse) Error() string {
	return fmt.Sprintf("protocol error 0x%02x: %s", e.Code, e.Detail)
}

// ParseErrorResponse extracts error info from an ERROR_RESP payload.
func ParseErrorResponse(payload []byte) *ErrorResponse {
	if len(payload) < 1 {
		return &ErrorResponse{Code: ErrInternal, Detail: "empty error payload"}
	}
	detail := ""
	if len(payload) > 1 {
		detail = string(payload[1:])
	}
	return &ErrorResponse{Code: payload[0], Detail: detail}
}

// SerializeKeyBundle serializes a KeyBundle for decryption on the Docker side.
func SerializeKeyBundle(b *KeyBundle) []byte {
	policySize := 1 + 1 + 2 + 2 + 4 + 2 + 8 // = 20
	totalSize := 8 + 8 + 8 + 2 + policySize +
		len(b.SessionTickets)*SessionTicketSize + RefreshTicketSize

	buf := make([]byte, totalSize)
	off := 0

	binary.BigEndian.PutUint64(buf[off:], b.BundleGen); off += 8
	binary.BigEndian.PutUint64(buf[off:], b.IssuedAtMs); off += 8
	binary.BigEndian.PutUint64(buf[off:], b.ExpireAtMs); off += 8
	binary.BigEndian.PutUint16(buf[off:], b.WorkerKID); off += 2

	// Policy
	buf[off] = b.Policy.TicketsPerBundle; off++
	buf[off] = 0; off++ // padding
	binary.BigEndian.PutUint16(buf[off:], b.Policy.QueriesPerTicket); off += 2
	binary.BigEndian.PutUint16(buf[off:], b.Policy.QueriesPerBundle); off += 2
	binary.BigEndian.PutUint32(buf[off:], b.Policy.MaxClockSkewMs); off += 4
	binary.BigEndian.PutUint16(buf[off:], b.Policy.AntiReplayWindow); off += 2
	binary.BigEndian.PutUint64(buf[off:], b.Policy.TicketLifetimeMs); off += 8

	for _, t := range b.SessionTickets {
		copy(buf[off:], EncodeSessionTicket(t))
		off += SessionTicketSize
	}

	copy(buf[off:], EncodeRefreshTicket(b.RefreshTicket))
	return buf
}

// DeserializeKeyBundle deserializes a KeyBundle.
func DeserializeKeyBundle(data []byte) (*KeyBundle, error) {
	if len(data) < 26 {
		return nil, errors.New("key bundle data too short")
	}

	b := &KeyBundle{}
	off := 0

	b.BundleGen = binary.BigEndian.Uint64(data[off:]); off += 8
	b.IssuedAtMs = binary.BigEndian.Uint64(data[off:]); off += 8
	b.ExpireAtMs = binary.BigEndian.Uint64(data[off:]); off += 8
	b.WorkerKID = binary.BigEndian.Uint16(data[off:]); off += 2

	// Policy
	b.Policy.TicketsPerBundle = data[off]; off++
	off++ // padding
	b.Policy.QueriesPerTicket = binary.BigEndian.Uint16(data[off:]); off += 2
	b.Policy.QueriesPerBundle = binary.BigEndian.Uint16(data[off:]); off += 2
	b.Policy.MaxClockSkewMs = binary.BigEndian.Uint32(data[off:]); off += 4
	b.Policy.AntiReplayWindow = binary.BigEndian.Uint16(data[off:]); off += 2
	b.Policy.TicketLifetimeMs = binary.BigEndian.Uint64(data[off:]); off += 8

	ticketCount := int(b.Policy.TicketsPerBundle)
	b.SessionTickets = make([]*SessionTicket, 0, ticketCount)
	for i := 0; i < ticketCount; i++ {
		if off+SessionTicketSize > len(data) {
			return nil, fmt.Errorf("not enough data for session ticket %d", i)
		}
		t, err := DecodeSessionTicket(data[off : off+SessionTicketSize])
		if err != nil {
			return nil, err
		}
		b.SessionTickets = append(b.SessionTickets, t)
		off += SessionTicketSize
	}

	if off+RefreshTicketSize > len(data) {
		return nil, errors.New("not enough data for refresh ticket")
	}
	rt, err := DecodeRefreshTicket(data[off : off+RefreshTicketSize])
	if err != nil {
		return nil, err
	}
	b.RefreshTicket = rt

	return b, nil
}
