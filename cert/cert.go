// Package cert provides certificate generation and management functions.
package cert

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"certforest/config"
)

// clockSkewTolerance is the time buffer for NotBefore to handle clock synchronization issues
const clockSkewTolerance = 5 * time.Minute

// GenerateCA generates a self-signed CA certificate using ECDSA
func GenerateCA(cfg *config.Config) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	// Generate ECDSA key pair with configured curve
	privateKey, err := ecdsa.GenerateKey(cfg.Curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Generate serial number (128-bit random, RFC 5280 compliant)
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial: %w", err)
	}

	// Generate Subject Key Identifier (RFC 5280 §4.2.1.2 - MUST for CA certificates)
	// Method 1: SHA-1 hash of the public key BIT STRING value
	ski, err := generateSKI(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate SKI: %w", err)
	}

	// Create certificate template
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               cfg.DN,
		NotBefore:             now.Add(-clockSkewTolerance), // Buffer for clock synchronization
		NotAfter:              now.AddDate(cfg.ValidityYears, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              cfg.KeyUsage,
		MaxPathLen:            0,    // Prevent creation of intermediate CAs
		MaxPathLenZero:        true, // Explicitly allow MaxPathLen=0
		SubjectKeyId:          ski,  // RFC 5280 §4.2.1.2
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return privateKey, cert, nil
}

// GenerateSigned generates a certificate signed by the CA using ECDSA
func GenerateSigned(cfg *config.Config, caKey *ecdsa.PrivateKey, caCert *x509.Certificate) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	// Generate ECDSA key pair with configured curve
	privateKey, err := ecdsa.GenerateKey(cfg.Curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Generate serial number (128-bit random, RFC 5280 compliant)
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial: %w", err)
	}

	// Generate Subject Key Identifier (RFC 5280 §4.2.1.2)
	ski, err := generateSKI(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate SKI: %w", err)
	}

	// Create certificate template
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               cfg.DN,
		NotBefore:             now.Add(-clockSkewTolerance), // Buffer for clock synchronization
		NotAfter:              now.AddDate(cfg.ValidityYears, 0, 0),
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              cfg.KeyUsage,
		ExtKeyUsage:           cfg.ExtKeyUsage,
		DNSNames:              cfg.DNSNames,
		IPAddresses:           cfg.IPAddresses,
		SubjectKeyId:          ski,                 // RFC 5280 §4.2.1.2
		AuthorityKeyId:        caCert.SubjectKeyId, // RFC 5280 §4.2.1.1
	}

	// Sign with CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &privateKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return privateKey, cert, nil
}

// SaveKeyPair saves the private key and certificate to files
func SaveKeyPair(dir, name string, key *ecdsa.PrivateKey, cert *x509.Certificate) error {
	// Save private key in PKCS#8 format (more universal than SEC 1/EC PRIVATE KEY)
	keyPath := filepath.Join(dir, name+".key")
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyFile.Close()

	// Use PKCS#8 format for better compatibility
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal PKCS#8 key: %w", err)
	}

	keyPEM := &pem.Block{
		Type:  "PRIVATE KEY", // PKCS#8 format
		Bytes: keyBytes,
	}
	if err := pem.Encode(keyFile, keyPEM); err != nil {
		return fmt.Errorf("failed to encode key: %w", err)
	}

	// Save certificate with explicit permissions (0644 for public cert)
	certPath := filepath.Join(dir, name+".crt")
	certFile, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %w", err)
	}
	defer certFile.Close()

	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	if err := pem.Encode(certFile, certPEM); err != nil {
		return fmt.Errorf("failed to encode cert: %w", err)
	}

	return nil
}

// generateSKI generates a Subject Key Identifier from an ECDSA public key
// per RFC 5280 §4.2.1.2 Method 1: SHA-1 hash of the BIT STRING subjectPublicKey
func generateSKI(pub *ecdsa.PublicKey) ([]byte, error) {
	// Marshal the public key to get the BIT STRING value
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	// SHA-1 hash of the public key (RFC 5280 Method 1)
	hash := sha1.Sum(pubBytes)
	return hash[:], nil
}
