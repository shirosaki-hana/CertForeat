// Package config provides configuration parsing for certificate generation.
package config

import (
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// YAMLConfig represents the root structure of the YAML configuration file
type YAMLConfig struct {
	Curve    string         `yaml:"curve"`
	Validity ValidityConfig `yaml:"validity"`
	DN       DNConfig       `yaml:"dn"`
	CA       CertConfig     `yaml:"ca"`
	Server   CertConfig     `yaml:"server"`
	Client   CertConfig     `yaml:"client"`
}

// ValidityConfig represents certificate validity periods in years
type ValidityConfig struct {
	CA     int `yaml:"ca"`
	Server int `yaml:"server"`
	Client int `yaml:"client"`
}

// DNConfig represents common Distinguished Name fields
type DNConfig struct {
	Country      string `yaml:"country"`
	State        string `yaml:"state"`
	Locality     string `yaml:"locality"`
	Organization string `yaml:"organization"`
}

// CertConfig represents certificate-specific configuration
type CertConfig struct {
	OrganizationalUnit string    `yaml:"organizational_unit"`
	CommonName         string    `yaml:"common_name"`
	KeyUsage           []string  `yaml:"key_usage"`
	ExtKeyUsage        []string  `yaml:"ext_key_usage"`
	AltNames           *AltNames `yaml:"alt_names,omitempty"`
}

// AltNames represents Subject Alternative Names
type AltNames struct {
	DNS []string `yaml:"dns"`
	IP  []string `yaml:"ip"`
}

// Config represents parsed certificate configuration for internal use
type Config struct {
	Curve         elliptic.Curve
	DN            pkix.Name
	IsCA          bool
	KeyUsage      x509.KeyUsage
	ExtKeyUsage   []x509.ExtKeyUsage
	DNSNames      []string
	IPAddresses   []net.IP
	ValidityYears int // Certificate validity period in years
}

// ParseYAML parses the YAML configuration file
func ParseYAML(filename string) (*YAMLConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg YAMLConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Set defaults
	if cfg.Curve == "" {
		cfg.Curve = "P-256"
	}

	// Default validity periods (in years)
	if cfg.Validity.CA == 0 {
		cfg.Validity.CA = 10 // CA: 10 years default
	}
	if cfg.Validity.Server == 0 {
		cfg.Validity.Server = 1 // Server: 1 year default
	}
	if cfg.Validity.Client == 0 {
		cfg.Validity.Client = 1 // Client: 1 year default
	}

	return &cfg, nil
}

// GetCAConfig extracts CA configuration
func (y *YAMLConfig) GetCAConfig() (*Config, error) {
	curve, err := parseCurve(y.Curve)
	if err != nil {
		return nil, err
	}

	return &Config{
		Curve:         curve,
		DN:            y.buildDN(y.CA.OrganizationalUnit, y.CA.CommonName),
		IsCA:          true,
		KeyUsage:      parseKeyUsageList(y.CA.KeyUsage),
		ExtKeyUsage:   parseExtKeyUsageList(y.CA.ExtKeyUsage),
		ValidityYears: y.Validity.CA,
	}, nil
}

// GetServerConfig extracts server certificate configuration
func (y *YAMLConfig) GetServerConfig() (*Config, error) {
	curve, err := parseCurve(y.Curve)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		Curve:         curve,
		DN:            y.buildDN(y.Server.OrganizationalUnit, y.Server.CommonName),
		IsCA:          false,
		KeyUsage:      parseKeyUsageList(y.Server.KeyUsage),
		ExtKeyUsage:   parseExtKeyUsageList(y.Server.ExtKeyUsage),
		ValidityYears: y.Validity.Server,
	}

	// Parse alt_names
	if y.Server.AltNames != nil {
		cfg.DNSNames = y.Server.AltNames.DNS
		for _, ipStr := range y.Server.AltNames.IP {
			if ip := net.ParseIP(ipStr); ip != nil {
				cfg.IPAddresses = append(cfg.IPAddresses, ip)
			}
		}
	}

	return cfg, nil
}

// GetClientConfig extracts client certificate configuration
func (y *YAMLConfig) GetClientConfig() (*Config, error) {
	curve, err := parseCurve(y.Curve)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		Curve:         curve,
		DN:            y.buildDN(y.Client.OrganizationalUnit, y.Client.CommonName),
		IsCA:          false,
		KeyUsage:      parseKeyUsageList(y.Client.KeyUsage),
		ExtKeyUsage:   parseExtKeyUsageList(y.Client.ExtKeyUsage),
		ValidityYears: y.Validity.Client,
	}

	// Parse alt_names if present
	if y.Client.AltNames != nil {
		cfg.DNSNames = y.Client.AltNames.DNS
		for _, ipStr := range y.Client.AltNames.IP {
			if ip := net.ParseIP(ipStr); ip != nil {
				cfg.IPAddresses = append(cfg.IPAddresses, ip)
			}
		}
	}

	return cfg, nil
}

// buildDN creates a pkix.Name from common DN and certificate-specific fields
func (y *YAMLConfig) buildDN(ou, cn string) pkix.Name {
	dn := pkix.Name{
		CommonName: cn,
	}

	if y.DN.Country != "" {
		dn.Country = []string{y.DN.Country}
	}
	if y.DN.State != "" {
		dn.Province = []string{y.DN.State}
	}
	if y.DN.Locality != "" {
		dn.Locality = []string{y.DN.Locality}
	}
	if y.DN.Organization != "" {
		dn.Organization = []string{y.DN.Organization}
	}
	if ou != "" {
		dn.OrganizationalUnit = []string{ou}
	}

	return dn
}

// parseCurve converts string curve name to elliptic.Curve
func parseCurve(name string) (elliptic.Curve, error) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "P-256", "P256", "PRIME256V1", "SECP256R1":
		return elliptic.P256(), nil
	case "P-384", "P384", "SECP384R1":
		return elliptic.P384(), nil
	case "P-521", "P521", "SECP521R1":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported curve: %s (supported: P-256, P-384, P-521)", name)
	}
}

// parseKeyUsageList converts string list to x509.KeyUsage
func parseKeyUsageList(usages []string) x509.KeyUsage {
	var ku x509.KeyUsage

	for _, usage := range usages {
		switch strings.ToLower(strings.TrimSpace(usage)) {
		case "digitalsignature":
			ku |= x509.KeyUsageDigitalSignature
		case "keyencipherment":
			ku |= x509.KeyUsageKeyEncipherment
		case "keycertsign":
			ku |= x509.KeyUsageCertSign
		case "crlsign":
			ku |= x509.KeyUsageCRLSign
		case "dataencipherment":
			ku |= x509.KeyUsageDataEncipherment
		case "keyagreement":
			ku |= x509.KeyUsageKeyAgreement
		case "contentcommitment":
			ku |= x509.KeyUsageContentCommitment
		case "encipheronly":
			ku |= x509.KeyUsageEncipherOnly
		case "decipheronly":
			ku |= x509.KeyUsageDecipherOnly
		}
	}

	return ku
}

// parseExtKeyUsageList converts string list to []x509.ExtKeyUsage
func parseExtKeyUsageList(usages []string) []x509.ExtKeyUsage {
	var eku []x509.ExtKeyUsage

	for _, usage := range usages {
		switch strings.ToLower(strings.TrimSpace(usage)) {
		case "serverauth":
			eku = append(eku, x509.ExtKeyUsageServerAuth)
		case "clientauth":
			eku = append(eku, x509.ExtKeyUsageClientAuth)
		case "codesigning":
			eku = append(eku, x509.ExtKeyUsageCodeSigning)
		case "emailprotection":
			eku = append(eku, x509.ExtKeyUsageEmailProtection)
		case "timestamping":
			eku = append(eku, x509.ExtKeyUsageTimeStamping)
		case "ocspsigning":
			eku = append(eku, x509.ExtKeyUsageOCSPSigning)
		}
	}

	return eku
}
