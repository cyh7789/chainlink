package gateway

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type JWTPayload struct {
	Digest         string `json:"digest"`
	Issuer         string `json:"iss"`
	IssueAtTime    int64  `json:"iat"`
	ExpirationTime int64  `json:"exp"`
	JwtID          string `json:"jti"`
}

func validateBearerJWT(header string, body []byte) error {
	header = strings.TrimSpace(header)
	if !strings.HasPrefix(header, "Bearer ") {
		return errors.New("invalid header")
	}
	jwt := header[len("Bearer "):]
	tokenParts := strings.Split(jwt, ".")
	if len(tokenParts) != 3 {
		return errors.New("invalid header")
	}

	jwtHeader, jwtPayload, jwtSignature := tokenParts[0], tokenParts[1], tokenParts[2]
	if err := validateJWTHeader(jwtHeader); err != nil {
		return err
	}

	payload, err := validateJWTPayload(jwtPayload, body)
	if err != nil {
		return err
	}

	return validateJWTSignature(jwtHeader, jwtPayload, jwtSignature, payload.Issuer)
}

func validateJWTHeader(header string) error {
	decoded, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return fmt.Errorf("failed to decode JWT header: %w", err)
	}
	var values map[string]string
	if err := json.Unmarshal(decoded, &values); err != nil {
		return err
	}
	if values["alg"] != "ETH" {
		return errors.New("invalid algorithm")
	}
	if values["typ"] != "JWT" {
		return errors.New("invalid type")
	}
	return nil
}

func validateJWTPayload(encodedPayload string, body []byte) (*JWTPayload, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var payload JWTPayload
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse JWT payload: %w", err)
	}

	// Validate iat
	if payload.IssueAtTime == 0 {
		return nil, errors.New("missing iat claim")
	}

	// Validate expiration
	if payload.ExpirationTime == 0 {
		return nil, errors.New("missing exp claim")
	}
	if time.Now().Unix() > payload.ExpirationTime {
		return nil, errors.New("JWT token has expired")
	}

	// Validate jti (non-empty, replay protection)
	if strings.TrimSpace(payload.JwtID) == "" {
		return nil, errors.New("missing jti claim")
	}

	// Validate iss (non-empty issuer/sender address)
	if strings.TrimSpace(payload.Issuer) == "" {
		return nil, errors.New("missing iss claim")
	}

	// Validate digest: SHA256 of the request body must match
	if strings.TrimSpace(payload.Digest) == "" {
		return nil, errors.New("missing digest claim")
	}
	hash := sha256.Sum256(body)
	expectedDigest := "0x" + hex.EncodeToString(hash[:])
	if !strings.EqualFold(payload.Digest, expectedDigest) {
		return nil, errors.New("invalid digest: request body hash mismatch")
	}

	return &payload, nil
}

func validateJWTSignature(encodedHeader, encodedPayload, encodedSignature, issuer string) error {
	// The message to sign is: base64url(header) + "." + base64url(payload)
	msg := encodedHeader + "." + encodedPayload

	// Apply Ethereum personal sign prefix
	prefixedMsg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(msg), msg)

	// Hash with Keccak256
	hash := crypto.Keccak256([]byte(prefixedMsg))

	// Decode the base64url-encoded signature
	sigBytes, err := base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil {
		return fmt.Errorf("failed to decode JWT signature: %w", err)
	}
	if len(sigBytes) != 65 {
		return errors.New("invalid signature length: expected 65 bytes")
	}

	// Normalize Ethereum recovery ID (some implementations use 27/28)
	if sigBytes[64] >= 27 {
		sigBytes[64] -= 27
	}

	// Recover public key from signature
	pubKey, err := crypto.SigToPub(hash, sigBytes)
	if err != nil {
		return fmt.Errorf("failed to recover public key from signature: %w", err)
	}

	// Derive the Ethereum address from the recovered public key
	recoveredAddr := crypto.PubkeyToAddress(*pubKey)

	// Compare to the issuer address from the payload
	expectedAddr := common.HexToAddress(issuer)
	if recoveredAddr != expectedAddr {
		return errors.New("signature verification failed: recovered address does not match issuer")
	}

	return nil
}
