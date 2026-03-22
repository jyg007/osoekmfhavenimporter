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
	"bytes"
	"compress/gzip"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
	"os"
	"sync"
	 "github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	ep11 "osoekmfhavenimporter/ep11"
    	"encoding/asn1"
    	"encoding/pem"
	"strings"
)

type InputKey struct {
	ID   string `json:"id"`
	Blob string `json:"blob"`
	Csum string `json:"csum"`
}

type ProcessedKey struct {
	KeyID  string
	Key    []byte
	Scheme string
}

type KeyBatch struct {
	Keys []InputKey
}

type ProcessResult struct {
	SuccessCount int      `json:"success_count"`
	FailedCount  int      `json:"failed_count"`
	FailedIDs    []string `json:"failed_ids"`
}


type ImportTx struct {
	ID        string      `json:"id"`        // document index / uuid
	Content   string      `json:"content"`   // gzipped base64 JSON array of keys
	Signature string      `json:"signature"` // empty for now
	Metadata  interface{} `json:"metadata"`  // static info
}

type TransportKey struct {
    ID         string
    WrappedKey string
}

var (
	db          *sql.DB
	target      ep11.Target_t
	wrappingKey []byte
	keyList     []InputKey
	keyListMu   sync.Mutex
	numAdapters int
    	rsaKeyPairRequested bool
    	rsaFlagMu           sync.Mutex
        transportKey   *TransportKey
        transportKeyMu sync.Mutex
)

func main() {
    mode := os.Getenv("mode")
    if mode == "" {
        log.Fatal("MODE environment variable not set (frontend or backend)")
    }

    var err error

    // Only initialize HSM for backend
    if mode == "backend" {
        hsmTarget := os.Getenv("EP11_IBM_TARGET_HSM")
        if hsmTarget == "" {
            log.Fatal("EP11_IBM_TARGET_HSM not set")
        }

        target = ep11.HsmInit(hsmTarget)

        numAdapters = 1
        for _, c := range hsmTarget {
            if c == ' ' {
                numAdapters++
            }
        }

        // Setup SQLite DB
        db, err = sql.Open("sqlite3", "./keys.db")
        if err != nil {
            panic(err)
        }
        defer db.Close()

        // Reset tables for backend
        _, err = db.Exec(`DROP TABLE IF EXISTS keys;
        CREATE TABLE keys (
            key_id TEXT PRIMARY KEY,
            key    BLOB NOT NULL,
            scheme TEXT NOT NULL
        );`)
        if err != nil {
            panic(err)
        }

        _, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS rsa_keys (
            key_id TEXT PRIMARY KEY,
            private_key BLOB NOT NULL
        );`)
        if err != nil {
            log.Fatal(err)
        }

        // Backend-specific handlers
        http.HandleFunc("/BackEndGetRSAKeyPair", BackEndGetRSAKeyPairHandler)
        http.HandleFunc("/BackendUploadTKey", setTransportKeyHandler)
        http.HandleFunc("/BackEndKeysImportFilesUpload", BackEndKeysImportFilesUploadHandler)
        http.HandleFunc("/BackendProcess", BackendProcessHandler)

        fmt.Println("Backend server listening on :9080")
        log.Fatal(http.ListenAndServe(":9080", nil))
    }

    if mode == "frontend" {
        // Frontend-specific handlers
        http.HandleFunc("/FrontEndCreateRSAKeyPairRequest", FrontEndCreateRSAKeyPairRequestHandler)
        http.HandleFunc("/FrontEndGetEMKFOSOMsgs", FrontEndGetEMKFOSOMsgsHandler)
        http.HandleFunc("/FrontEndUpload", FrontEndUploadHandler)
        http.HandleFunc("/FrontEndUploadTKEY", FrontEndUploadTKEYHandler)

        fmt.Println("Frontend server listening on :8080")
        log.Fatal(http.ListenAndServe(":8080", nil))
    }
}


//
// 1) SET TRANSPORT KEY
//
func setTransportKeyHandler(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
                http.Error(w, "POST only", http.StatusMethodNotAllowed)
                return
        }

        var payload struct {
                ID        string `json:"id"`
                Content   string `json:"content"`
                Signature string `json:"signature"`
                Metadata  string `json:"metadata"`
        }

        if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
                http.Error(w, "Invalid JSON", http.StatusBadRequest)
                return
        }

        if payload.ID == "" || payload.Content == "" {
                http.Error(w, "Missing id or content", http.StatusBadRequest)
                return
        }

        // Decode wrapped key (hex)
        data, err := hex.DecodeString(payload.Content)
        if err != nil {
                http.Error(w, "Invalid wrapped key hex", http.StatusBadRequest)
                return
        }

        //------------------------------------------------------------------
        // Retrieve RSA private key using ID
        //------------------------------------------------------------------
        var key []byte
	keyID := strings.TrimPrefix(payload.ID, "ekmfimport-tkey-")

	err = db.QueryRow(
	    `SELECT private_key FROM rsa_keys WHERE key_id = ?`,
	    keyID,
	).Scan(&key)
        
	if err != nil {
                if err == sql.ErrNoRows {
                        http.Error(w,"rsa key not found ", http.StatusBadRequest)
			return
                }
        }

        //------------------------------------------------------------------
        // Unwrap AES transport key using RSA-OAEP
        //------------------------------------------------------------------
        unwrapKeyTemplate := ep11.Attributes{
                C.CKA_CLASS:       C.CKO_SECRET_KEY,
                C.CKA_KEY_TYPE:    C.CKK_AES,
                C.CKA_VALUE_LEN:   32,
                C.CKA_WRAP:        true,
                C.CKA_UNWRAP:      true,
                C.CKA_ENCRYPT:     true,
                C.CKA_EXTRACTABLE: false,
        }

        unwrapKey, csum, err := ep11.UnWrapKey(
                target,
                ep11.Mech(
                        C.CKM_RSA_PKCS_OAEP,
                        ep11.NewOAEPParams(C.CKM_SHA256, C.CKG_MGF1_SHA256, 0, nil),
                ),
                key,
                data,
                unwrapKeyTemplate,
        )

        if err != nil {
                http.Error(w, err.Error(), http.StatusInternalServerError)
                return
        }

        //------------------------------------------------------------------
        // Store transport key in memory (thread-safe)
        //------------------------------------------------------------------
        keyListMu.Lock()
        wrappingKey = unwrapKey
        keyListMu.Unlock()

        //------------------------------------------------------------------
        // Response
        //------------------------------------------------------------------
	// 1. Create the inner content first
	innerContent := map[string]string{
	    "status":   "ok",
	    "checksum": fmt.Sprintf("%x", csum),
	}

	// 2. Marshal inner content to a string
	contentBytes, _ := json.Marshal(innerContent)

	// 3. Build the final response
	resp := map[string]interface{}{
	    "id":       payload.ID,
	    "content":  string(contentBytes), 
	    "signature":   "",
	    "metadata": "EKMFIMPORT",
	}

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(resp)
}

//
// 2) UPLOAD KEYS (gzip+base64 JSON array)
//
func FrontEndUploadHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		JsonGzipBase64 string `json:"json_gzip_base64"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	gzipBytes, err := base64.StdEncoding.DecodeString(payload.JsonGzipBase64)
	if err != nil {
		http.Error(w, "Invalid base64", http.StatusBadRequest)
		return
	}

	reader, err := gzip.NewReader(bytes.NewReader(gzipBytes))
	if err != nil {
		http.Error(w, "Invalid gzip", http.StatusBadRequest)
		return
	}
	defer reader.Close()

	var keys []InputKey
	if err := json.NewDecoder(reader).Decode(&keys); err != nil {
		http.Error(w, "Invalid JSON inside gzip", http.StatusBadRequest)
		return
	}

	keyListMu.Lock()
	keyList = append(keyList, keys...)
	keyListMu.Unlock()

	fmt.Fprintf(w, "Uploaded %d keys\n", len(keys))
}

//
// 3) PROCESS
//
func BackendProcessHandler(w http.ResponseWriter, r *http.Request) {
	
	keyListMu.Lock()
	if wrappingKey == nil {
		keyListMu.Unlock()
		http.Error(w, "Transport key not set", http.StatusBadRequest)
		log.Println("[BackendProcess] Transport key not set, flushing import messages")
		keyListMu.Lock()
		keyList = nil
		keyListMu.Unlock()
		return
	}
	keyListMu.Unlock()

	batchSize := 100000
	fmt.Sscanf(r.URL.Query().Get("batch_size"), "%d", &batchSize)
	if batchSize <= 0 {
		batchSize = 100000
	}

	keyListMu.Lock()
	if len(keyList) == 0 {
		keyListMu.Unlock()
		http.Error(w, "No keys uploaded", http.StatusBadRequest)
		log.Println("[BackendProcess] No Keys uploaded")
		return
	}

	keys := make([]InputKey, len(keyList))
	copy(keys, keyList)
	keyListMu.Unlock()

	jobCh := make(chan KeyBatch, (len(keys)+batchSize-1)/batchSize)
	resultCh := make(chan ProcessedKey, len(keys))
	failedCh := make(chan string, len(keys))

	var writerWG sync.WaitGroup
	writerWG.Add(1)

	var successCount int
	go batchWriter(resultCh, &writerWG, &successCount)

	numWorkers := numAdapters * 8
	log.Printf("starting %d workers", numWorkers)

	var workerWG sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		workerWG.Add(1)
		go worker(jobCh, resultCh, failedCh, &workerWG)
	}

	for i := 0; i < len(keys); i += batchSize {
		end := i + batchSize
		if end > len(keys) {
			end = len(keys)
		}
		jobCh <- KeyBatch{Keys: keys[i:end]}
	}
	close(jobCh)

	workerWG.Wait()
	close(resultCh)
	close(failedCh)
	writerWG.Wait()

	var failedIDs []string
	for f := range failedCh {
		failedIDs = append(failedIDs, f)
	}

	// 1. Create the detailed result object
	result := ProcessResult{
	    SuccessCount: successCount,
	    FailedCount:  len(failedIDs),
	    FailedIDs:    failedIDs,
	}
        log.Printf("Keys import finished: %d successful, %d failed", result.SuccessCount, result.FailedCount)

	// 2. Marshal the result to a JSON string for the "content" field
	resultBytes, _ := json.Marshal(result)

	// 3. Build the final envelope response
	finalResp := map[string]interface{}{
	    // Using a standard ISO-like timestamp for the ID
	    "id":        time.Now().Format("20060102-150405"), 
	    "content":   string(resultBytes),
	    "signature": "",
	    "metadata":  "EKMFKEYSIMPORT",
	}

	// Flushing imported messages
	keyListMu.Lock()
	keyList = nil
	wrappingKey = nil
	keyListMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(finalResp)
}

//
// WORKER
//
func worker(jobs <-chan KeyBatch, results chan<- ProcessedKey, failed chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()

	for batch := range jobs {
		for _, k := range batch.Keys {

			data, err := hex.DecodeString(k.Blob)
			if err != nil {
				log.Printf("failed to decode hex blob for key %s: %v", k.ID, err)
				failed <- k.ID
				continue
			}

			keyTemplate := ep11.Attributes{
				C.CKA_CLASS:     C.CKO_SECRET_KEY,
				C.CKA_KEY_TYPE:  C.CKK_GENERIC_SECRET,
				C.CKA_VALUE_LEN: 32,
			}

			iv := make([]byte, 16)

			keyBlob, csum, err := ep11.UnWrapKey(
				target,
				ep11.Mech(C.CKM_AES_CBC_PAD, iv),
				wrappingKey,
				data,
				keyTemplate,
			)
			if err != nil {
				log.Printf("failed to unwrap key %s: %v", k.ID, err)
				failed <- k.ID
				continue
			}

			csumHex := hex.EncodeToString(csum[:3])
			if csumHex != k.Csum {
				log.Printf("checksum mismatch for key %s", k.ID)
				failed <- k.ID
				continue
			}

			results <- ProcessedKey{
				KeyID:  k.ID,
				Key:    keyBlob,
				Scheme: "SEED",
			}
		}
	}
}

//
// SQLITE WRITER
//
func batchWriter(results <-chan ProcessedKey, wg *sync.WaitGroup, successCount *int) {
	defer wg.Done()

	tx, err := db.Begin()
	if err != nil {
		return
	}

	stmt, err := tx.Prepare("INSERT OR REPLACE INTO keys(key_id,key,scheme) VALUES(?,?,?)")
	if err != nil {
		return
	}
	defer stmt.Close()

	count := 0

	for r := range results {
		stmt.Exec(r.KeyID, r.Key, r.Scheme)
		count++
	}

	tx.Commit()
	*successCount = count
}

func FrontEndGetEMKFOSOMsgsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}

	// parse keys_per_doc query parameter
	keysPerDoc := 1000
	fmt.Sscanf(r.URL.Query().Get("keys_per_doc"), "%d", &keysPerDoc)
	if keysPerDoc <= 0 {
		keysPerDoc = 1000
	}

	// --- snapshot & empty keyList atomically ---
	keyListMu.Lock()
	keysSnapshot := make([]InputKey, len(keyList)) // <- same type as keyList
	copy(keysSnapshot, keyList)
	keyList = nil // empty the list safely
	keyListMu.Unlock()

	nKeys := len(keysSnapshot)
	var docs []ImportTx

	for i := 0; i < nKeys; i += keysPerDoc {
		end := i + keysPerDoc
		if end > nKeys {
			end = nKeys
		}

		keysSlice := keysSnapshot[i:end]

		// JSON encode the keys slice
		jsonBytes, err := json.Marshal(keysSlice)
		if err != nil {
			http.Error(w, "Failed to encode keys", http.StatusInternalServerError)
			return
		}

		// gzip compress
		var buf bytes.Buffer
		gzipWriter := gzip.NewWriter(&buf)
		_, err = gzipWriter.Write(jsonBytes)
		if err != nil {
			http.Error(w, "Failed to gzip keys", http.StatusInternalServerError)
			return
		}
		gzipWriter.Close()

		// base64 encode
		b64Content := base64.StdEncoding.EncodeToString(buf.Bytes())

		// create a document
		docs = append(docs, ImportTx{
			ID:        "ekmfimport-"+uuid.New().String(),
			Content:   b64Content,
			Signature: "",
			Metadata:  "EKMFKEYSIMPORT",
		})
	}


	// Check if RSA key pair request was made
	rsaFlagMu.Lock()
	if rsaKeyPairRequested {
	        // Add EKMFGENRSAKEYPAIR document
        	docs = append(docs, ImportTx{
	            ID:        fmt.Sprintf("ekmfimport-rsa-%d", time.Now().UnixNano()),
        	    Content:   "EKMFGENRSAKEYPAIR",
	            Signature: "",
        	    Metadata:  "EKMFIMPORT",
	        })
        	rsaKeyPairRequested = false // clear the flag
	    }
	rsaFlagMu.Unlock()

	// Check if Transport Key Messages are set
	transportKeyMu.Lock()
	if transportKey != nil {
	    docs = append(docs, ImportTx{
        	ID:        "ekmfimport-tkey-"+transportKey.ID,
	        Content:   transportKey.WrappedKey,
        	Signature: "",
	        Metadata:  "EKMFTKEY",
	    })
    	    // clear the key after returning
    	    transportKey = nil
	}
	transportKeyMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(docs)
}

func BackEndKeysImportFilesUploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var doc ImportTx
	if err := json.NewDecoder(r.Body).Decode(&doc); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// decode base64
	gzipBytes, err := base64.StdEncoding.DecodeString(doc.Content)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid base64 for doc %s: %v", doc.ID, err), http.StatusBadRequest)
		return
	}

	// ungzip
	reader, err := gzip.NewReader(bytes.NewReader(gzipBytes))
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid gzip for doc %s: %v", doc.ID, err), http.StatusBadRequest)
		return
	}
	defer reader.Close()

	var keys []InputKey
	if err := json.NewDecoder(reader).Decode(&keys); err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON inside doc %s: %v", doc.ID, err), http.StatusBadRequest)
		return
	}

	keyListMu.Lock()
	keyList = append(keyList, keys...)
	keyListMu.Unlock()

	fmt.Fprintf(w, "Uploaded %d keys from document %s\n", len(keys), doc.ID)
}



func BackEndGetRSAKeyPairHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "POST only", http.StatusMethodNotAllowed)
        return
    }

    // Decode incoming JSON
    var req struct {
        ID       string `json:"id"`
        Content  string `json:"content"`
        Signature string `json:"signature"`
        Metadata string `json:"metadata"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }

    if req.Content != "EKMFGENRSAKEYPAIR" {
        http.Error(w, "Unsupported content value", http.StatusBadRequest)
        return
    }

    // --- Generate RSA key pair ---
    publicExponent := 65537
    keySize := 4096

    publicKeyTemplate := ep11.Attributes{
        C.CKA_ENCRYPT:         true,
        C.CKA_WRAP:            true,
        C.CKA_MODULUS_BITS:    keySize,
        C.CKA_PUBLIC_EXPONENT: publicExponent,
    }

    privateKeyTemplate := ep11.Attributes{
        C.CKA_PRIVATE:   true,
        C.CKA_SENSITIVE: true,
        C.CKA_DECRYPT:   true,
        C.CKA_UNWRAP:    true,
    }

    pk, sk, err := ep11.GenerateKeyPair(target, ep11.Mech(C.CKM_RSA_PKCS_KEY_PAIR_GEN, nil), publicKeyTemplate, privateKeyTemplate)
    if err != nil {
        log.Printf("Failed to generate RSA key pair: %v", err)
        http.Error(w, "Failed to generate RSA key pair", http.StatusInternalServerError)
        return
    }

    // Generate UUID key ID
    // Store private key in SQLite

    keyID := strings.TrimPrefix(req.ID, "ekmfimport-")

    _, err = db.Exec("INSERT INTO rsa_keys(key_id, private_key) VALUES(?, ?)", keyID, sk)
    if err != nil {
        log.Printf("Failed to store private key: %v", err)
        http.Error(w, "Failed to store private key", http.StatusInternalServerError)
        return
    }

    // Convert public key to PEM (SPKI)
    var spki asn1.RawValue
    rest, err := asn1.Unmarshal(pk, &spki)
    if err != nil {
        log.Printf("Failed to parse SPKI DER: %v", err)
        http.Error(w, "Failed to parse public key", http.StatusInternalServerError)
        return
    }

    pemBlock := &pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: pk[:len(pk)-len(rest)],
    }
    publicPEM := string(pem.EncodeToMemory(pemBlock))

    // --- Return ImportTx style JSON ---
    resp := map[string]interface{}{
        "id":       req.ID,
        "content":  publicPEM,
        "signature": "",
        "metadata": "EKMFRSAIMPORT",
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(resp)
}

func FrontEndCreateRSAKeyPairRequestHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "POST only", http.StatusMethodNotAllowed)
        return
    }

    rsaFlagMu.Lock()
    rsaKeyPairRequested = true
    rsaFlagMu.Unlock()

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "status": "RSA key pair request registered",
    })
}

func FrontEndUploadTKEYHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "POST only", http.StatusMethodNotAllowed)
        return
    }

    var req struct {
        KeyID      string `json:"keyid"`
        WrappedKey string `json:"wrappedkey"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }

    if req.KeyID == "" || req.WrappedKey == "" {
        http.Error(w, "keyid and wrappedkey required", http.StatusBadRequest)
        return
    }

    transportKeyMu.Lock()
    transportKey = &TransportKey{
        ID:         req.KeyID,
        WrappedKey: req.WrappedKey,
    }
    transportKeyMu.Unlock()

    log.Printf("Transport key set for RSA key: %s", req.KeyID)

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "status": "transport key loaded",
        "id":     "ekmfimport-tkey-"+req.KeyID,
    })
}
