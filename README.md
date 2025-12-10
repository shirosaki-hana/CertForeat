# CertForest - mTLS Certificate Generator

A simple certificate generator for mTLS (mutual TLS) authentication, powered by Go's `crypto/x509` package with ECDSA (Elliptic Curve Digital Signature Algorithm).

## Features

- **ECDSA Support** - Modern elliptic curve cryptography (P-256, P-384, P-521)
- **Root CA Generation** - Create your own Certificate Authority
- **Server Certificates** - With SAN (Subject Alternative Names) support
- **Client Certificates** - For mTLS client authentication
- **Single YAML Configuration** - All certificates configured in one file

## Quick Start

### 1. Setup Configuration

Copy the example configuration file and customize it:

```bash
cp certforest.yaml.example certforest.yaml
```

### 2. Build & Run

```bash
go build -o certforest .
./certforest
```

Or specify a custom config file:

```bash
./certforest my-config.yaml
```

### 3. Output

Generated certificates will be in the `certificate/` directory:

```
certificate/
├── ca.crt          # Root CA certificate
├── ca.key          # Root CA private key
├── server.crt      # Server certificate
├── server.key      # Server private key
├── client.crt      # Client certificate
└── client.key      # Client private key
```

## Configuration

### Example Configuration (`certforest.yaml`)

```yaml
# Elliptic curve (P-256, P-384, P-521)
curve: P-256

# Common Distinguished Name (DN) - shared by all certificates
dn:
  country: US
  state: California
  locality: San Francisco
  organization: My Organization

# Root CA configuration
ca:
  organizational_unit: Certificate Authority
  common_name: My Root CA
  key_usage:
    - keyCertSign
    - cRLSign

# Server certificate configuration
server:
  organizational_unit: Web Server
  common_name: localhost
  key_usage:
    - digitalSignature
    - keyEncipherment
  ext_key_usage:
    - serverAuth
  alt_names:
    dns:
      - localhost
      - example.com
    ip:
      - 127.0.0.1

# Client certificate configuration
client:
  organizational_unit: Client Certificate
  common_name: my-client
  key_usage:
    - digitalSignature
    - keyEncipherment
  ext_key_usage:
    - clientAuth
```

### Elliptic Curves

| Curve | Security Level | Recommended For |
|-------|---------------|-----------------|
| P-256 | ~128 bits | General use (default) |
| P-384 | ~192 bits | High security |
| P-521 | ~256 bits | Maximum security |

### Key Usage Options

| Key Usage | Description |
|-----------|-------------|
| `digitalSignature` | For signing data |
| `keyEncipherment` | For encrypting keys |
| `keyCertSign` | For signing certificates (CA only) |
| `cRLSign` | For signing CRLs (CA only) |
| `dataEncipherment` | For encrypting data |
| `keyAgreement` | For key agreement protocols |

### Extended Key Usage Options

| Extended Key Usage | Description |
|-------------------|-------------|
| `serverAuth` | TLS server authentication |
| `clientAuth` | TLS client authentication |
| `codeSigning` | Code signing |
| `emailProtection` | Email protection (S/MIME) |
| `timeStamping` | Trusted timestamping |
| `ocspSigning` | OCSP signing |

## Usage

### Import CA Certificate

Add `ca.crt` to your system's trusted certificate store or browser.

### Server Configuration (Go example)

```go
cert, _ := tls.LoadX509KeyPair("certificate/server.crt", "certificate/server.key")
caCert, _ := os.ReadFile("certificate/ca.crt")
caCertPool := x509.NewCertPool()
caCertPool.AppendCertsFromPEM(caCert)

tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    ClientCAs:    caCertPool,
    ClientAuth:   tls.RequireAndVerifyClientCert,
}
```

### Client Configuration (Go example)

```go
cert, _ := tls.LoadX509KeyPair("certificate/client.crt", "certificate/client.key")
caCert, _ := os.ReadFile("certificate/ca.crt")
caCertPool := x509.NewCertPool()
caCertPool.AppendCertsFromPEM(caCert)

tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    RootCAs:      caCertPool,
}
```

## Project Structure

```
.
├── main.go                    # Entry point
├── certforest.yaml.example    # Configuration template
├── config/
│   └── config.go              # YAML configuration parsing
└── cert/
    └── cert.go                # Certificate generation
```

## License

MIT License
