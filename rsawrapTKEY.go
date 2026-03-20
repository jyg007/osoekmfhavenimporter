package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/hex"
    "encoding/json"
    "encoding/pem"
    "fmt"
    "log"
    "os"
)

func loadRSAPublicKeyFromPEM(pemData []byte) (*rsa.PublicKey, error) {

    block, _ := pem.Decode(pemData)
    if block == nil {
        return nil, fmt.Errorf("invalid PEM file")
    }

    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return nil, err
    }

    rsaPub, ok := pub.(*rsa.PublicKey)
    if !ok {
        return nil, fmt.Errorf("not an RSA public key")
    }

    return rsaPub, nil
}

func main() {

	// We now expect 4 arguments: program name, pem file, keyID, and the hex key
	if len(os.Args) != 4 {
		log.Fatal("usage: program <public.pem> <keyid> <32byte_hex_key>")
	}

	pemPath := os.Args[1]
	keyID := os.Args[2]
	hexInput := os.Args[3]

	// 1. Load the PEM file
	pemData, err := os.ReadFile(pemPath)
	if err != nil {
		log.Fatal("Error reading PEM:", err)
	}

	pk, err := loadRSAPublicKeyFromPEM(pemData)
	if err != nil {
		log.Fatal("Error loading public key:", err)
	}

	// 2. Decode the hex string into bytes
	aesKey, err := hex.DecodeString(hexInput)
	if err != nil {
		log.Fatal("Invalid hex string:", err)
	}

	// 3. Validation: Ensure it is exactly 32 bytes (256 bits)
	if len(aesKey) != 32 {
		log.Fatalf("Error: Key must be 32 bytes (64 hex characters), got %d bytes", len(aesKey))
	}

	fmt.Printf("Successfully loaded key for ID: %s\n", keyID)


    // Generate AES-256 key
    //aesKey := make([]byte, 32)
    //if _, err := rand.Read(aesKey); err != nil {
    //    log.Fatal(err)
    //}

    // Wrap AES key
    wrappedKey, err := rsa.EncryptOAEP(
        sha256.New(),
        rand.Reader,
        pk,
        aesKey,
        nil,
    )
    if err != nil {
        log.Fatal(err)
    }

    // Prepare JSON output
    output := map[string]string{
        "keyid":      keyID,
        "wrappedkey": hex.EncodeToString(wrappedKey),
    }

    jsonData, err := json.Marshal(output)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(string(jsonData))
}
