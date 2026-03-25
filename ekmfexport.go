package main

/*
#cgo LDFLAGS: -lep11
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ep11.h>
*/
import "C"

import (
	"encoding/hex"
	"encoding/json"
	"osoekmfhavenimporter/ep11"
	"fmt"
	"os"
	"strconv"
        "github.com/google/uuid"
	"log"
)

type KeyOutput struct {
	KeyID       string `json:"id"`
	BlobWrapped string `json:"blob"`
	Checksum    string `json:"csum"`
}

func main() {

	if len(os.Args) < 3 {
		panic("usage: <program> <transportkey hex> <num_keys>")
	}

	// Transport key
	transportkey, err := hex.DecodeString(os.Args[1])
	if err != nil {
		panic(fmt.Errorf("invalid transport key: %s", err))
	}

	// Number of keys
	n, err := strconv.Atoi(os.Args[2])
	if err != nil || n <= 0 {
		panic("invalid number of keys")
	}

	// Retrieve the HSM target from the environment variable
	hsmTarget := os.Getenv("EP11_IBM_TARGET_HSM")

	// Optional: Fallback if the variable is empty
	if hsmTarget == "" {
	    log.Fatalf("EP11_IBM_TARGET_HSM not set, using default: %s", hsmTarget)
	        
	}

	target := ep11.HsmInit(hsmTarget)

	// This slice will hold the full JSON array
	results := make([]KeyOutput, 0, n)

	for i := 0; i < n; i++ {

//		keyID := []byte(fmt.Sprintf("key-%d", i))
		id, err := uuid.NewV7()
		if err != nil {
		    panic(err)
		}

		keyID := []byte(id.String())

		keyTemplate := ep11.Attributes{
			C.CKA_CLASS:     C.CKO_SECRET_KEY,
			C.CKA_KEY_TYPE:  C.CKK_AES,
			C.CKA_VALUE_LEN: 32,
		}

		key, csum, err := ep11.GenerateKey(
			target,
			ep11.Mech(C.CKM_AES_KEY_GEN, nil),
			keyTemplate,
		)
		if err != nil {
			panic(fmt.Errorf("GenerateKey error (key %d): %s", i, err))
		}

		iv := make([]byte, 16)

		blobWrapped, err := ep11.WrapKey(
			target,
			ep11.Mech(C.CKM_AES_CBC_PAD, iv),
			transportkey,
			key,
		)
		if err != nil {
			panic(fmt.Errorf("WrapKey error (key %d): %s", i, err))
		}

		results = append(results, KeyOutput{
			KeyID:       string(keyID),
			BlobWrapped: hex.EncodeToString(blobWrapped),
			Checksum:    hex.EncodeToString(csum[:3]), // first 3 bytes only
		})
	}

	// Output one valid JSON array
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(results); err != nil {
		panic(fmt.Errorf("JSON encode error: %s", err))
	}
}
