
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
	"bufio"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
        "ep11go/ep11"

	_ "github.com/mattn/go-sqlite3"

)

type InputKey struct {
	KeyID       string `json:"key_id"`
	BlobWrapped string `json:"blob_wrapped"`
	Checksum    string `json:"checksum"`
}

func main() {
	if len(os.Args) < 3 {
		panic("usage: <program> <wrapping_key_hex> <input_file>")
	}

	// 🔑 AES wrapping key
	aeskey, err := hex.DecodeString(os.Args[1])
	if err != nil {
		panic(fmt.Errorf("invalid AES key: %s", err))
	}

	// 📂 Input file
	file, err := os.Open(os.Args[2])
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// 🗄️ SQLite DB
	db, err := sql.Open("sqlite3", "./keys.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// Create table
	_, err = db.Exec(`
	DROP TABLE IF EXISTS keys;
	CREATE TABLE IF NOT EXISTS keys (
		key_id TEXT NOT NULL PRIMARY KEY,
		key    BLOB NOT NULL,
		scheme TEXT NOT NULL
	);
	`)
	if err != nil {
		panic(err)
	}

	// Prepare insert
	stmt, err := db.Prepare("INSERT OR REPLACE INTO keys(key_id, key, scheme) VALUES (?, ?, ?)")
	if err != nil {
		panic(err)
	}
	defer stmt.Close()

	target := ep11.HsmInit("3.19")

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Bytes()

		var in InputKey
		if err := json.Unmarshal(line, &in); err != nil {
			fmt.Printf("Skipping invalid JSON: %s\n", err)
			continue
		}

		// Decode wrapped blob
		data, err := hex.DecodeString(in.BlobWrapped)
		if err != nil {
			fmt.Printf("Invalid hex for key %s\n", in.KeyID)
			continue
		}

		// Generic key template
		keyTemplate := ep11.Attributes{
			C.CKA_CLASS:    C.CKO_SECRET_KEY,
			C.CKA_KEY_TYPE: C.CKK_GENERIC_SECRET,
		}

		iv := make([]byte, 16)

		// 🔓 Unwrap
		keyBlob, csum, err := ep11.UnWrapKey(
			target,
			ep11.Mech(C.CKM_AES_CBC_PAD, iv),
			aeskey,
			data,
			keyTemplate,
		)
		if err != nil {
			fmt.Printf("Unwrap failed for %s: %s\n", in.KeyID, err)
			continue
		}
		// Compute hex strings for comparison
		csumHex := hex.EncodeToString(csum[:3])
		expectedCsum := in.Checksum

		// Compare
		if csumHex != expectedCsum {
		    fmt.Printf("WARNING: Checksum mismatch for key %s (got=%s, expected=%s)\n",
		        in.KeyID, csumHex, expectedCsum)
		    continue // optionally skip inserting this key
		}

		// 💾 Store in DB
		_, err = stmt.Exec(in.KeyID, []byte(keyBlob), "SEED")
		if err != nil {
			fmt.Printf("DB insert failed for %s: %s\n", in.KeyID, err)
			continue
		}

//		fmt.Printf("Imported key %x (checksum=%x)\n", keyBlob, csum)
	}

	if err := scanner.Err(); err != nil {
		panic(err)
	}
}
