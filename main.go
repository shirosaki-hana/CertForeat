package main

import (
	"fmt"
	"os"
	"path/filepath"

	"certforest/cert"
	"certforest/config"
)

const defaultConfigFile = "certforest.yaml"

func main() {
	fmt.Println("╔═══════════════════════════════════════════════════╗")
	fmt.Println("║          CertForest                               ║")
	fmt.Println("║          Certificate Generator for mTLS           ║")
	fmt.Println("║          Powered by Go crypto/x509                ║")
	fmt.Println("╚═══════════════════════════════════════════════════╝")
	fmt.Println()

	// Determine config file path
	configFile := defaultConfigFile
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}

	// Parse YAML configuration
	fmt.Printf("Loading configuration: %s\n", configFile)
	yamlConfig, err := config.ParseYAML(configFile)
	if err != nil {
		fmt.Printf("Failed to parse %s: %v\n", configFile, err)
		os.Exit(1)
	}

	// Create output directory
	outDir := "certificate"
	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Printf("Failed to create directory: %v\n", err)
		os.Exit(1)
	}

	// Generate Root CA
	fmt.Println("[1/3] Generating Root CA...")
	caConfig, err := yamlConfig.GetCAConfig()
	if err != nil {
		fmt.Printf("Failed to get CA config: %v\n", err)
		os.Exit(1)
	}
	caKey, caCert, err := cert.GenerateCA(caConfig)
	if err != nil {
		fmt.Printf("Failed to generate CA: %v\n", err)
		os.Exit(1)
	}
	if err := cert.SaveKeyPair(outDir, "ca", caKey, caCert); err != nil {
		fmt.Printf("Failed to save CA: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("CA Certificate: %s\n", filepath.Join(outDir, "ca.crt"))
	fmt.Printf("CA Private Key: %s\n", filepath.Join(outDir, "ca.key"))

	// Generate Server Certificate
	fmt.Println("[2/3] Generating Server Certificate...")
	serverConfig, err := yamlConfig.GetServerConfig()
	if err != nil {
		fmt.Printf("Failed to get server config: %v\n", err)
		os.Exit(1)
	}
	serverKey, serverCert, err := cert.GenerateSigned(serverConfig, caKey, caCert)
	if err != nil {
		fmt.Printf("Failed to generate server cert: %v\n", err)
		os.Exit(1)
	}
	if err := cert.SaveKeyPair(outDir, "server", serverKey, serverCert); err != nil {
		fmt.Printf("Failed to save server cert: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Server Certificate: %s\n", filepath.Join(outDir, "server.crt"))
	fmt.Printf("Server Private Key: %s\n", filepath.Join(outDir, "server.key"))

	// Generate Client Certificate
	fmt.Println("[3/3] Generating Client Certificate...")
	clientConfig, err := yamlConfig.GetClientConfig()
	if err != nil {
		fmt.Printf("Failed to get client config: %v\n", err)
		os.Exit(1)
	}
	clientKey, clientCert, err := cert.GenerateSigned(clientConfig, caKey, caCert)
	if err != nil {
		fmt.Printf("Failed to generate client cert: %v\n", err)
		os.Exit(1)
	}
	if err := cert.SaveKeyPair(outDir, "client", clientKey, clientCert); err != nil {
		fmt.Printf("Failed to save client cert: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Client Certificate: %s\n", filepath.Join(outDir, "client.crt"))
	fmt.Printf("Client Private Key: %s\n", filepath.Join(outDir, "client.key"))

	fmt.Println()
	fmt.Println("All certificates generated.")
	fmt.Printf("Output directory: %s\n", outDir)
}
