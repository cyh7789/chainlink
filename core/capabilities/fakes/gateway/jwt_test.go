package gateway

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestKey creates a fresh ECDSA private key for use in tests.
func generateTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	return key
}

// buildJWT constructs a signed JWT from header, payload, and a private key.
// Returns the full "Bearer <token>" header value.
func buildJWT(t *testing.T, key *ecdsa.PrivateKey, body []byte, opts ...func(*JWTPayload)) string {
	t.Helper()

	now := time.Now().Unix()
	hash := sha256.Sum256(body)
	digest := "0x" + hex.EncodeToString(hash[:])
	addr := crypto.PubkeyToAddress(key.PublicKey).Hex()

	payload := &JWTPayload{
		Digest:         digest,
		Issuer:         addr,
		IssueAtTime:    now,
		ExpirationTime: now + 300,
		JwtID:          "test-jti",
	}
	for _, o := range opts {
		o(payload)
	}

	headerJSON, err := json.Marshal(map[string]string{"alg": "ETH", "typ": "JWT"})
	require.NoError(t, err)
	payloadJSON, err := json.Marshal(payload)
	require.NoError(t, err)

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)

	msg := encodedHeader + "." + encodedPayload
	prefixedMsg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(msg), msg)
	msgHash := crypto.Keccak256([]byte(prefixedMsg))

	sig, err := crypto.Sign(msgHash, key)
	require.NoError(t, err)

	encodedSig := base64.RawURLEncoding.EncodeToString(sig)
	token := encodedHeader + "." + encodedPayload + "." + encodedSig
	return "Bearer " + token
}

// TestValidateBearerJWT_Valid verifies that a well-formed JWT passes validation
// and returns the correct public key (Ethereum address).
func TestValidateBearerJWT_Valid(t *testing.T) {
	key := generateTestKey(t)
	body := []byte(`{"jsonrpc":"2.0","id":"1","method":"trigger"}`)
	header := buildJWT(t, key, body)

	authKey, err := validateBearerJWT(header, body)
	require.NoError(t, err)
	require.NotNil(t, authKey)

	expectedAddr := strings.ToLower(crypto.PubkeyToAddress(key.PublicKey).Hex())
	assert.Equal(t, strings.ToLower(expectedAddr), strings.ToLower(authKey.PublicKey))
}

// TestValidateBearerJWT_MissingBearerPrefix checks that a token without the
// "Bearer " prefix is rejected.
func TestValidateBearerJWT_MissingBearerPrefix(t *testing.T) {
	key := generateTestKey(t)
	body := []byte(`{}`)
	fullHeader := buildJWT(t, key, body)
	// strip "Bearer "
	token := strings.TrimPrefix(fullHeader, "Bearer ")

	_, err := validateBearerJWT(token, body)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid header")
}

// TestValidateBearerJWT_WrongPartCount checks that a JWT with the wrong number
// of dot-delimited parts is rejected.
func TestValidateBearerJWT_WrongPartCount(t *testing.T) {
	_, err := validateBearerJWT("Bearer only.two", []byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid header")
}

// TestValidateBearerJWT_ExpiredToken verifies that an expired token is rejected.
func TestValidateBearerJWT_ExpiredToken(t *testing.T) {
	key := generateTestKey(t)
	body := []byte(`{}`)
	past := time.Now().Unix() - 600
	header := buildJWT(t, key, body, func(p *JWTPayload) {
		p.IssueAtTime = past - 60
		p.ExpirationTime = past
	})

	_, err := validateBearerJWT(header, body)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

// TestValidateBearerJWT_FutureIAT verifies that a token with an iat far in the
// future is rejected.
func TestValidateBearerJWT_FutureIAT(t *testing.T) {
	key := generateTestKey(t)
	body := []byte(`{}`)
	future := time.Now().Unix() + 120
	header := buildJWT(t, key, body, func(p *JWTPayload) {
		p.IssueAtTime = future
		p.ExpirationTime = future + 300
	})

	_, err := validateBearerJWT(header, body)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "iat is in the future")
}

// TestValidateBearerJWT_DigestMismatch verifies that a JWT whose digest does
// not match the supplied body is rejected.
func TestValidateBearerJWT_DigestMismatch(t *testing.T) {
	key := generateTestKey(t)
	body := []byte(`{"real":"body"}`)
	header := buildJWT(t, key, body)

	differentBody := []byte(`{"other":"body"}`)
	_, err := validateBearerJWT(header, differentBody)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "digest")
}

// TestValidateBearerJWT_WrongSigner verifies that a JWT signed by a different
// key than the one in the issuer claim is rejected.
func TestValidateBearerJWT_WrongSigner(t *testing.T) {
	signerKey := generateTestKey(t)
	claimedKey := generateTestKey(t)
	body := []byte(`{}`)

	// Build a JWT where the payload claims claimedKey's address, but the
	// signature is produced by signerKey.
	now := time.Now().Unix()
	hash := sha256.Sum256(body)
	digest := "0x" + hex.EncodeToString(hash[:])

	payload := JWTPayload{
		Digest:         digest,
		Issuer:         crypto.PubkeyToAddress(claimedKey.PublicKey).Hex(), // claimed address
		IssueAtTime:    now,
		ExpirationTime: now + 300,
		JwtID:          "test-jti",
	}

	headerJSON, err := json.Marshal(map[string]string{"alg": "ETH", "typ": "JWT"})
	require.NoError(t, err)
	payloadJSON, err := json.Marshal(payload)
	require.NoError(t, err)

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	msg := encodedHeader + "." + encodedPayload
	prefixedMsg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(msg), msg)
	msgHash := crypto.Keccak256([]byte(prefixedMsg))

	sig, err := crypto.Sign(msgHash, signerKey) // sign with different key
	require.NoError(t, err)

	token := "Bearer " + encodedHeader + "." + encodedPayload + "." + base64.RawURLEncoding.EncodeToString(sig)
	_, err = validateBearerJWT(token, body)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match issuer")
}

// --- validateJWTHeader ---

func TestValidateJWTHeader_Valid(t *testing.T) {
	h, err := json.Marshal(map[string]string{"alg": "ETH", "typ": "JWT"})
	require.NoError(t, err)
	err = validateJWTHeader(base64.RawURLEncoding.EncodeToString(h))
	assert.NoError(t, err)
}

func TestValidateJWTHeader_InvalidBase64(t *testing.T) {
	err := validateJWTHeader("!not-valid-base64!")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode JWT header")
}

func TestValidateJWTHeader_InvalidJSON(t *testing.T) {
	err := validateJWTHeader(base64.RawURLEncoding.EncodeToString([]byte("not json")))
	require.Error(t, err)
}

func TestValidateJWTHeader_WrongAlgorithm(t *testing.T) {
	h, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	require.NoError(t, err)
	err = validateJWTHeader(base64.RawURLEncoding.EncodeToString(h))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid algorithm")
}

func TestValidateJWTHeader_WrongType(t *testing.T) {
	h, err := json.Marshal(map[string]string{"alg": "ETH", "typ": "JWS"})
	require.NoError(t, err)
	err = validateJWTHeader(base64.RawURLEncoding.EncodeToString(h))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid type")
}

// --- validateJWTPayload ---

func encodePayload(t *testing.T, p JWTPayload) string {
	t.Helper()
	b, err := json.Marshal(p)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(b)
}

func validPayload(body []byte) JWTPayload {
	now := time.Now().Unix()
	hash := sha256.Sum256(body)
	return JWTPayload{
		Digest:         "0x" + hex.EncodeToString(hash[:]),
		Issuer:         "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF",
		IssueAtTime:    now,
		ExpirationTime: now + 300,
		JwtID:          "unique-id",
	}
}

func TestValidateJWTPayload_Valid(t *testing.T) {
	body := []byte(`hello`)
	p := validPayload(body)
	result, err := validateJWTPayload(encodePayload(t, p), body)
	require.NoError(t, err)
	assert.Equal(t, p.Issuer, result.Issuer)
}

func TestValidateJWTPayload_InvalidBase64(t *testing.T) {
	_, err := validateJWTPayload("!bad!", []byte(`x`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode JWT payload")
}

func TestValidateJWTPayload_InvalidJSON(t *testing.T) {
	_, err := validateJWTPayload(base64.RawURLEncoding.EncodeToString([]byte("not json")), []byte(`x`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse JWT payload")
}

func TestValidateJWTPayload_MissingIAT(t *testing.T) {
	body := []byte(`x`)
	p := validPayload(body)
	p.IssueAtTime = 0
	_, err := validateJWTPayload(encodePayload(t, p), body)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing iat claim")
}

func TestValidateJWTPayload_IATInFuture(t *testing.T) {
	body := []byte(`x`)
	p := validPayload(body)
	p.IssueAtTime = time.Now().Unix() + 120
	p.ExpirationTime = p.IssueAtTime + 300
	_, err := validateJWTPayload(encodePayload(t, p), body)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "iat is in the future")
}

func TestValidateJWTPayload_MissingEXP(t *testing.T) {
	body := []byte(`x`)
	p := validPayload(body)
	p.ExpirationTime = 0
	_, err := validateJWTPayload(encodePayload(t, p), body)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing exp claim")
}

func TestValidateJWTPayload_EXPBeforeIAT(t *testing.T) {
	body := []byte(`x`)
	p := validPayload(body)
	p.ExpirationTime = p.IssueAtTime - 1
	_, err := validateJWTPayload(encodePayload(t, p), body)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exp is before iat")
}

func TestValidateJWTPayload_Expired(t *testing.T) {
	body := []byte(`x`)
	p := validPayload(body)
	p.IssueAtTime = time.Now().Unix() - 600
	p.ExpirationTime = time.Now().Unix() - 300
	_, err := validateJWTPayload(encodePayload(t, p), body)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestValidateJWTPayload_MissingJTI(t *testing.T) {
	body := []byte(`x`)
	p := validPayload(body)
	p.JwtID = ""
	_, err := validateJWTPayload(encodePayload(t, p), body)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing jti claim")
}

func TestValidateJWTPayload_MissingISS(t *testing.T) {
	body := []byte(`x`)
	p := validPayload(body)
	p.Issuer = ""
	_, err := validateJWTPayload(encodePayload(t, p), body)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing iss claim")
}

func TestValidateJWTPayload_MissingDigest(t *testing.T) {
	body := []byte(`x`)
	p := validPayload(body)
	p.Digest = ""
	_, err := validateJWTPayload(encodePayload(t, p), body)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing digest claim")
}

func TestValidateJWTPayload_DigestMismatch(t *testing.T) {
	body := []byte(`x`)
	p := validPayload(body)
	p.Digest = "0x" + strings.Repeat("aa", 32)
	_, err := validateJWTPayload(encodePayload(t, p), body)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hash mismatch")
}

// --- validateJWTSignature ---

func TestValidateJWTSignature_Valid(t *testing.T) {
	key := generateTestKey(t)
	addr := crypto.PubkeyToAddress(key.PublicKey).Hex()

	encodedHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ETH","typ":"JWT"}`))
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + addr + `"}`))
	msg := encodedHeader + "." + encodedPayload
	prefixedMsg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(msg), msg)
	msgHash := crypto.Keccak256([]byte(prefixedMsg))
	sig, err := crypto.Sign(msgHash, key)
	require.NoError(t, err)

	encodedSig := base64.RawURLEncoding.EncodeToString(sig)
	err = validateJWTSignature(encodedHeader, encodedPayload, encodedSig, addr)
	assert.NoError(t, err)
}

func TestValidateJWTSignature_InvalidBase64(t *testing.T) {
	err := validateJWTSignature("hdr", "pld", "!bad-sig!", "0x0000")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode JWT signature")
}

func TestValidateJWTSignature_WrongLength(t *testing.T) {
	shortSig := base64.RawURLEncoding.EncodeToString([]byte("tooshort"))
	err := validateJWTSignature("hdr", "pld", shortSig, "0x0000")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signature length")
}

func TestValidateJWTSignature_WrongSigner(t *testing.T) {
	signerKey := generateTestKey(t)
	claimedAddr := crypto.PubkeyToAddress(generateTestKey(t).PublicKey).Hex()

	encodedHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ETH","typ":"JWT"}`))
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + claimedAddr + `"}`))
	msg := encodedHeader + "." + encodedPayload
	prefixedMsg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(msg), msg)
	msgHash := crypto.Keccak256([]byte(prefixedMsg))
	sig, err := crypto.Sign(msgHash, signerKey)
	require.NoError(t, err)

	encodedSig := base64.RawURLEncoding.EncodeToString(sig)
	err = validateJWTSignature(encodedHeader, encodedPayload, encodedSig, claimedAddr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match issuer")
}
