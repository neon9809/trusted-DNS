package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// HKDFDerive derives a key from rootSeed using HKDF-SHA256.
func HKDFDerive(rootSeed []byte, info string, length int) ([]byte, error) {
	salt := make([]byte, 32) // fixed zero salt
	r := hkdf.New(sha256.New, rootSeed, salt, []byte(info))
	key := make([]byte, length)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf derive failed: %w", err)
	}
	return key, nil
}

// DerivedKeys holds all purpose-specific keys derived from root_seed.
type DerivedKeys struct {
	BootstrapKey   []byte
	TicketAuthKey  []byte
	RefreshAuthKey []byte
	BundleWrapKey  []byte
}

// DeriveAllKeys derives all purpose-specific keys from root_seed.
func DeriveAllKeys(rootSeed []byte) (*DerivedKeys, error) {
	bk, err := HKDFDerive(rootSeed, "trusted-dns/bootstrap", 32)
	if err != nil {
		return nil, err
	}
	tk, err := HKDFDerive(rootSeed, "trusted-dns/ticket-mac", 32)
	if err != nil {
		return nil, err
	}
	rk, err := HKDFDerive(rootSeed, "trusted-dns/refresh-mac", 32)
	if err != nil {
		return nil, err
	}
	wk, err := HKDFDerive(rootSeed, "trusted-dns/bundle-wrap", 32)
	if err != nil {
		return nil, err
	}
	return &DerivedKeys{
		BootstrapKey:   bk,
		TicketAuthKey:  tk,
		RefreshAuthKey: rk,
		BundleWrapKey:  wk,
	}, nil
}

// QueryKeys holds the per-ticket query phase keys.
type QueryKeys struct {
	ReqKey  []byte
	RespKey []byte
}

// DeriveQueryKeys derives query-phase keys from a session ticket's resume_seed.
func DeriveQueryKeys(resumeSeed []byte) (*QueryKeys, error) {
	reqKey, err := HKDFDerive(resumeSeed, "trusted-dns/query/req", 32)
	if err != nil {
		return nil, err
	}
	respKey, err := HKDFDerive(resumeSeed, "trusted-dns/query/resp", 32)
	if err != nil {
		return nil, err
	}
	return &QueryKeys{ReqKey: reqKey, RespKey: respKey}, nil
}

// DeriveClientID derives a stable 32-byte client_id from root_seed.
func DeriveClientID(rootSeed []byte) ([]byte, error) {
	return HKDFDerive(rootSeed, "trusted-dns/client-id", ClientIDSize)
}

// AEADEncrypt encrypts plaintext with AES-256-GCM.
func AEADEncrypt(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("aes new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("gcm new: %w", err)
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("nonce gen: %w", err)
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
	return nonce, ciphertext, nil
}

// AEADDecrypt decrypts ciphertext with AES-256-GCM.
func AEADDecrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm new: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("gcm open: %w", err)
	}
	return plaintext, nil
}

// ComputeTicketTag computes HMAC-SHA256 tag (first 16 bytes) for ticket auth.
func ComputeTicketTag(authKey, data []byte) []byte {
	mac := hmac.New(sha256.New, authKey)
	mac.Write(data)
	full := mac.Sum(nil)
	return full[:TicketTagSize]
}

// VerifyTicketTag verifies an HMAC-SHA256 tag.
func VerifyTicketTag(authKey, data, expectedTag []byte) bool {
	computed := ComputeTicketTag(authKey, data)
	return hmac.Equal(computed, expectedTag)
}

// ComputeBootstrapProof computes a bootstrap proof from bootstrap_key, nonce, and timestamp.
func ComputeBootstrapProof(bootstrapKey, bootNonce []byte, timestampMs uint64) []byte {
	data := make([]byte, len(bootNonce)+8)
	copy(data, bootNonce)
	binary.BigEndian.PutUint64(data[len(bootNonce):], timestampMs)
	return ComputeTicketTag(bootstrapKey, data)
}

// ComputeRefreshProof computes a refresh proof.
func ComputeRefreshProof(refreshAuthKey, refreshSeed []byte, spentBundleGen uint64, spentQueryCount uint32) []byte {
	data := make([]byte, len(refreshSeed)+12)
	copy(data, refreshSeed)
	binary.BigEndian.PutUint64(data[len(refreshSeed):], spentBundleGen)
	binary.BigEndian.PutUint32(data[len(refreshSeed)+8:], spentQueryCount)
	return ComputeTicketTag(refreshAuthKey, data)
}

// RandomBytes generates n random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// HexToBytes converts a hex string to bytes.
func HexToBytes(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// BytesToHex converts bytes to a hex string.
func BytesToHex(b []byte) string {
	return hex.EncodeToString(b)
}
