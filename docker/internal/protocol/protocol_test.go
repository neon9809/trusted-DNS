package protocol

import (
	"bytes"
	"testing"
)

func TestHeaderEncodeDecode(t *testing.T) {
	h := &Header{
		Ver:            ProtocolVersion,
		MsgType:        MsgQueryReq,
		Flags:          0x0001,
		BundleGen:      42,
		TicketID:       3,
		Seq:            100,
		PayloadLen:     512,
		HeaderMAC:      0,
	}
	copy(h.ClientIDPrefix[:], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})

	encoded := EncodeHeader(h)
	if len(encoded) != HeaderSize {
		t.Fatalf("expected header size %d, got %d", HeaderSize, len(encoded))
	}

	decoded, err := DecodeHeader(encoded)
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}

	if decoded.Ver != h.Ver {
		t.Errorf("ver: got %d, want %d", decoded.Ver, h.Ver)
	}
	if decoded.MsgType != h.MsgType {
		t.Errorf("msg_type: got %d, want %d", decoded.MsgType, h.MsgType)
	}
	if decoded.BundleGen != h.BundleGen {
		t.Errorf("bundle_gen: got %d, want %d", decoded.BundleGen, h.BundleGen)
	}
	if decoded.TicketID != h.TicketID {
		t.Errorf("ticket_id: got %d, want %d", decoded.TicketID, h.TicketID)
	}
	if decoded.Seq != h.Seq {
		t.Errorf("seq: got %d, want %d", decoded.Seq, h.Seq)
	}
	if decoded.PayloadLen != h.PayloadLen {
		t.Errorf("payload_len: got %d, want %d", decoded.PayloadLen, h.PayloadLen)
	}
	if decoded.ClientIDPrefix != h.ClientIDPrefix {
		t.Errorf("client_id_prefix mismatch")
	}
}

func TestSessionTicketEncodeDecode(t *testing.T) {
	ticket := &SessionTicket{
		TicketID:    1,
		Slot:        0,
		Reserved:    0,
		BundleGen:   5,
		NotBeforeMs: 1000000,
		NotAfterMs:  2000000,
		QueryBudget: 200,
		CounterBase: 0,
	}
	copy(ticket.ClientID[:], bytes.Repeat([]byte{0xAB}, 32))
	copy(ticket.ResumeSeed[:], bytes.Repeat([]byte{0xCD}, 32))
	copy(ticket.TicketTag[:], bytes.Repeat([]byte{0xEF}, 16))

	encoded := EncodeSessionTicket(ticket)
	if len(encoded) != SessionTicketSize {
		t.Fatalf("expected ticket size %d, got %d", SessionTicketSize, len(encoded))
	}

	decoded, err := DecodeSessionTicket(encoded)
	if err != nil {
		t.Fatalf("decode session ticket: %v", err)
	}

	if decoded.TicketID != ticket.TicketID {
		t.Errorf("ticket_id: got %d, want %d", decoded.TicketID, ticket.TicketID)
	}
	if decoded.BundleGen != ticket.BundleGen {
		t.Errorf("bundle_gen: got %d, want %d", decoded.BundleGen, ticket.BundleGen)
	}
	if decoded.QueryBudget != ticket.QueryBudget {
		t.Errorf("query_budget: got %d, want %d", decoded.QueryBudget, ticket.QueryBudget)
	}
	if decoded.ClientID != ticket.ClientID {
		t.Errorf("client_id mismatch")
	}
	if decoded.ResumeSeed != ticket.ResumeSeed {
		t.Errorf("resume_seed mismatch")
	}
}

func TestRefreshTicketEncodeDecode(t *testing.T) {
	ticket := &RefreshTicket{
		BundleGen:          3,
		NotBeforeMs:        1000000,
		NotAfterMs:         2000000,
		RotateAfterQueries: 1000,
	}
	copy(ticket.ClientID[:], bytes.Repeat([]byte{0x11}, 32))
	copy(ticket.RefreshNonce[:], bytes.Repeat([]byte{0x22}, 16))
	copy(ticket.RefreshSeed[:], bytes.Repeat([]byte{0x33}, 32))
	copy(ticket.RefreshTag[:], bytes.Repeat([]byte{0x44}, 16))

	encoded := EncodeRefreshTicket(ticket)
	if len(encoded) != RefreshTicketSize {
		t.Fatalf("expected size %d, got %d", RefreshTicketSize, len(encoded))
	}

	decoded, err := DecodeRefreshTicket(encoded)
	if err != nil {
		t.Fatalf("decode refresh ticket: %v", err)
	}

	if decoded.BundleGen != ticket.BundleGen {
		t.Errorf("bundle_gen: got %d, want %d", decoded.BundleGen, ticket.BundleGen)
	}
	if decoded.RotateAfterQueries != ticket.RotateAfterQueries {
		t.Errorf("rotate_after: got %d, want %d", decoded.RotateAfterQueries, ticket.RotateAfterQueries)
	}
}

func TestAEADEncryptDecrypt(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	plaintext := []byte("hello trusted-dns")
	aad := []byte("additional-data")

	nonce, ciphertext, err := AEADEncrypt(key, plaintext, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	decrypted, err := AEADDecrypt(key, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted mismatch: got %q, want %q", decrypted, plaintext)
	}

	// Tamper with ciphertext
	ciphertext[0] ^= 0xFF
	_, err = AEADDecrypt(key, nonce, ciphertext, aad)
	if err == nil {
		t.Error("expected decrypt failure with tampered ciphertext")
	}
}

func TestHKDFDerive(t *testing.T) {
	seed := bytes.Repeat([]byte{0x01}, 32)

	key1, err := HKDFDerive(seed, "trusted-dns/bootstrap", 32)
	if err != nil {
		t.Fatalf("derive key1: %v", err)
	}

	key2, err := HKDFDerive(seed, "trusted-dns/ticket-mac", 32)
	if err != nil {
		t.Fatalf("derive key2: %v", err)
	}

	// Different info strings should produce different keys
	if bytes.Equal(key1, key2) {
		t.Error("different info strings produced same key")
	}

	// Same info string should produce same key
	key1b, err := HKDFDerive(seed, "trusted-dns/bootstrap", 32)
	if err != nil {
		t.Fatalf("derive key1b: %v", err)
	}
	if !bytes.Equal(key1, key1b) {
		t.Error("same info string produced different keys")
	}
}

func TestTicketTag(t *testing.T) {
	key := bytes.Repeat([]byte{0xAA}, 32)
	data := []byte("ticket-data-to-authenticate")

	tag := ComputeTicketTag(key, data)
	if len(tag) != TicketTagSize {
		t.Fatalf("tag size: got %d, want %d", len(tag), TicketTagSize)
	}

	if !VerifyTicketTag(key, data, tag) {
		t.Error("valid tag verification failed")
	}

	// Tamper with data
	tampered := make([]byte, len(data))
	copy(tampered, data)
	tampered[0] ^= 0xFF
	if VerifyTicketTag(key, tampered, tag) {
		t.Error("tampered data should fail verification")
	}
}

func TestBootstrapProof(t *testing.T) {
	key := bytes.Repeat([]byte{0xBB}, 32)
	nonce := bytes.Repeat([]byte{0xCC}, BootNonceSize)
	timestamp := uint64(1700000000000)

	proof := ComputeBootstrapProof(key, nonce, timestamp)
	if len(proof) != TicketTagSize {
		t.Fatalf("proof size: got %d, want %d", len(proof), TicketTagSize)
	}

	// Verify deterministic
	proof2 := ComputeBootstrapProof(key, nonce, timestamp)
	if !bytes.Equal(proof, proof2) {
		t.Error("bootstrap proof is not deterministic")
	}

	// Different timestamp should produce different proof
	proof3 := ComputeBootstrapProof(key, nonce, timestamp+1)
	if bytes.Equal(proof, proof3) {
		t.Error("different timestamps produced same proof")
	}
}

func TestDeriveClientID(t *testing.T) {
	seed := bytes.Repeat([]byte{0xDD}, 32)

	id, err := DeriveClientID(seed)
	if err != nil {
		t.Fatalf("derive client id: %v", err)
	}

	if len(id) != ClientIDSize {
		t.Fatalf("client id size: got %d, want %d", len(id), ClientIDSize)
	}

	// Deterministic
	id2, err := DeriveClientID(seed)
	if err != nil {
		t.Fatalf("derive client id 2: %v", err)
	}
	if !bytes.Equal(id, id2) {
		t.Error("client id derivation is not deterministic")
	}
}
