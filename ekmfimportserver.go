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
)

type InputKey struct {
	ID   string `json:"id"`
	Blob string `json:"blob"`
	Csum string `json:"csum"`
}

type EKMFCmd struct {
    Content   string                 `json:"Content"`
    Signature string                 `json:"Signature"`
    Metadata  map[string]interface{} `json:"Metadata"`
}

func (c EKMFCmd) MetadataJSON() string {
    b, _ := json.Marshal(c.Metadata)
    return string(b)
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

type OSODoc struct {
	ID        string      `json:"id"`        // document index / uuid
	Content   string      `json:"content"`   // gzipped base64 JSON array of keys
	Signature string      `json:"signature"` // empty for now
	Metadata  string       `json:"metadata"`  // static info
}

type Meta struct {
	Type  string `json:"type"`
	KeyID string `json:"keyid"`
}

var (
	db     		     	*sql.DB
	target      		ep11.Target_t
	wrappingKey 		[]byte
	keyList     		[]InputKey
	keyListMu   		sync.Mutex
	numAdapters 		int
 	TxList      		[]OSODoc
	ekmfCmdQueue 		[]EKMFCmd
    queueMutex   		sync.Mutex
)

// **************************************************************************************************************
// **************************************************************************************************************
// **************************************************************************************************************
// **************************************************************************************************************
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
        // To_EKMF
		http.HandleFunc("/BackendPostEKMFMsg", BackendEKMFMsgHandler)
        http.HandleFunc("/BackendEKMFImport", BackendProcessHandler)

        // To_oso
        http.HandleFunc("/BackendGetEKMFMsgs", BackendGetCompletedHandler)

        fmt.Println("Backend server listening on :9080")
        log.Fatal(http.ListenAndServe(":9080", nil))
    }

    if mode == "frontend" {
        // EKMF Upload Msg
        http.HandleFunc("/FrontendUpload",  FrontendUploadHandler)
        http.HandleFunc("/FrontendEKMFCmd", FrontendEKMFCmdHandler)
        // to_oso
        http.HandleFunc("/FrontendGetMsgs", FrontendGetEKMFMsgsHandler)

        fmt.Println("Frontend server listening on :8080")
        log.Fatal(http.ListenAndServe(":8080", nil))
    }
}

func BackendEKMFMsgHandler(w http.ResponseWriter, r *http.Request) {
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

    if payload.ID == ""  {
            http.Error(w, "Missing id", http.StatusBadRequest)
            return
    }

  // --- Parse metadata ---
    var meta struct {
        Type string `json:"type"`
        // add other fields if needed
    }

    if err := json.Unmarshal([]byte(payload.Metadata), &meta); err != nil {
        http.Error(w, "Invalid metadata JSON", http.StatusBadRequest)
        return
    }

    // --- Call different functions depending on metadata.type ---
    switch meta.Type {
    case "EKMFGENRSAKEYPAIR":
         if err := EKMFGenRsaKeyPair(payload); err != nil {
        	http.Error(w, err.Error(), http.StatusBadRequest)
        	return
    	}
 	case "EKMFLIST":
         if err := EKMFCenc0(payload); err != nil {
        	http.Error(w, err.Error(), http.StatusBadRequest)
        	return
    	}
 
    case "EKMFTKEY":
         if err := EKMFStoreTkey(payload); err != nil {
        	http.Error(w, err.Error(), http.StatusBadRequest)
        	return
    	}
    case "EKMFKEYSIMPORT":
         if err := EKMFImportkeys(payload); err != nil {
        	http.Error(w, err.Error(), http.StatusBadRequest)
        	return
    	}
   
    default:
        http.Error(w, "Unknown type in metadata", http.StatusBadRequest)
        return
    }
 
	w.WriteHeader(http.StatusNoContent) 
}

// **************************************************************************************************************
// 1) SET TRANSPORT KEY
// **************************************************************************************************************
func EKMFStoreTkey(req OSODoc) error  {
    // --- Decode wrapped key (hex) ---
    data, err := hex.DecodeString(req.Content)
    if err != nil {
        return fmt.Errorf("invalid wrapped key hex: %w", err)
    }

    // --- Parse metadata ---
    var meta Meta
    if req.Metadata != "" {
        if err := json.Unmarshal([]byte(req.Metadata), &meta); err != nil {
            return fmt.Errorf("invalid metadata JSON: %w", err)
        }
    }

    keyID := meta.KeyID
    if keyID == "" {
        return fmt.Errorf("metadata missing keyID")
    }

    // --- Retrieve RSA private key using ID ---
    var key []byte
    err = db.QueryRow(`SELECT private_key FROM rsa_keys WHERE key_id = ?`, keyID).Scan(&key)
    if err != nil {
        if err == sql.ErrNoRows {
            return fmt.Errorf("rsa key not found for keyID=%s", keyID)
        }
        return fmt.Errorf("db query error: %w", err)
    }

    // --- Unwrap AES transport key using RSA-OAEP ---
    unwrapKeyTemplate := ep11.Attributes{
        C.CKA_CLASS:       C.CKO_SECRET_KEY,
        C.CKA_KEY_TYPE:    C.CKK_AES,
        C.CKA_VALUE_LEN:   32,
        C.CKA_WRAP:        true,
        C.CKA_UNWRAP:      true,
        C.CKA_ENCRYPT:     true,
        C.CKA_DECRYPT:     true,
        C.CKA_EXTRACTABLE: false,
    }

    unwrapKey, csum, err := ep11.UnWrapKey(
        target,
        ep11.Mech(C.CKM_RSA_PKCS_OAEP, ep11.NewOAEPParams(C.CKM_SHA256, C.CKG_MGF1_SHA256, 0, nil)),
        key,
        data,
        unwrapKeyTemplate,
    )
    if err != nil {
        return fmt.Errorf("failed to unwrap key: %w", err)
    }

    // --- Store transport key in memory thread-safe and delete private key from DB ---
    keyListMu.Lock()
    defer keyListMu.Unlock()

    _, err = db.Exec(`DELETE FROM rsa_keys WHERE key_id = ?`, keyID)
    if err != nil {
        log.Printf("Failed to delete rsa key %s: %v", keyID, err)
        return fmt.Errorf("failed to delete rsa key: %w", err)
    }
    log.Printf("Private key deleted for keyID=%s", keyID)

    wrappingKey = unwrapKey

    // --- Build response ---
    innerContent := map[string]string{
        "status":   "ok",
        "checksum": fmt.Sprintf("%x", csum),
    }
    contentBytes, _ := json.Marshal(innerContent)

    metaResp := map[string]string{
        "keyid":  keyID,
        "source": "EKMF",
        "type":   "EKMFTKEY",
    }
    metaRespJSON, err := json.Marshal(metaResp)
    if err != nil {
        return fmt.Errorf("failed to build metadata JSON: %w", err)
    }

    resp := OSODoc{
        ID:        req.ID,
        Content:   string(contentBytes),
        Signature: "",
        Metadata:  string(metaRespJSON),
    }
    TxList = append(TxList, resp)

    return nil
}


type Job struct {
    KeyID string
    Key   []byte
}

type Result struct {
    KeyID string
    Cenc0 string
}

func computeCENC0(key []byte) string {

    // 16-byte zero block (AES block size)
    zeroBlock := make([]byte, 16)

    // Encrypt zero block using AES-ECB
    cipher, err := ep11.EncryptSingle(
        target,
        ep11.Mech(C.CKM_AES_ECB, nil),
        key,
        zeroBlock,
    )
    if err != nil {
        log.Fatalf("Encryption failed: %v", err)
    }

    return hex.EncodeToString(cipher[:3])
}

func workercenc0(jobs <-chan Job, results chan<- Result, wg *sync.WaitGroup) {
    defer wg.Done()

    for j := range jobs {
        cenc0 := computeCENC0(j.Key)
        results <- Result{KeyID: j.KeyID, Cenc0: cenc0}
    }
}


func EKMFCenc0(doc OSODoc) error {

    workers := 8*numAdapters

    jobs := make(chan Job, 20000)
    results := make(chan Result, 20000)

    var wg sync.WaitGroup

    // Start workers
    for i := 0; i < workers; i++ {
        wg.Add(1)
        go workercenc0(jobs, results, &wg)
    }

    // --- Collect results in memory ---
    var resultList []Result
    var collectorWG sync.WaitGroup
    collectorWG.Add(1)

    go func() {
        defer collectorWG.Done()
        for r := range results {
            resultList = append(resultList, r)
        }
    }()

    // --- SQLite reader ---
    rows, err := db.Query("SELECT key_id, key FROM keys WHERE scheme='SEED'")
    if err != nil {
        return err
    }
    defer rows.Close()

    for rows.Next() {
        var j Job
        if err := rows.Scan(&j.KeyID, &j.Key); err != nil {
            return err
        }
        jobs <- j
    }

    close(jobs)
    wg.Wait()
    close(results)
    collectorWG.Wait()

    log.Println("[CENC0] Total keys processed:", len(resultList))

    // --- Metadata ---
    metaResp := map[string]string{
        "type":   "EKMFLIST",
        "source": "EKMF",
    }

    metaRespJSON, err := json.Marshal(metaResp)
    if err != nil {
        return  fmt.Errorf("failed to build metadata JSON: %w", err)
    }
	contentJSON, err := json.Marshal(resultList)
	if err != nil {
	    return fmt.Errorf("failed to marshal result list: %w", err)
	}

	resp := OSODoc{
	    ID:        doc.ID,
	    Content:   string(contentJSON),   // now it matches the struct
	    Signature: "",
	    Metadata:  string(metaRespJSON),
	}
 
  
    TxList = append(TxList, resp)

    return nil
}


// **************************************************************************************************************
// PROCESS
// **************************************************************************************************************
func BackendProcessHandler(w http.ResponseWriter, r *http.Request) {
	
	keyListMu.Lock()
	if wrappingKey == nil {
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

        meta := map[string]string{
                "source": "EKMF",   // only if you also want the same field as Python
                "type": "EKMFIMPORTRESULT",
        }
        metaJSON, err := json.Marshal(meta)
                if err != nil {
                http.Error(w, "Failed to build metadata", http.StatusInternalServerError)
                return
        }

	// 3. Build the final envelope response
	finalResp := OSODoc{
	    ID:        uuid.New().String(),
	    Content:   string(resultBytes),
	    Signature: "",
	    Metadata:  string(metaJSON),  // string, since your OSODoc.Metadata is string
	}
	// Flushing imported messages
	keyListMu.Lock()
	keyList = nil
	wrappingKey = nil
	keyListMu.Unlock()

	TxList = append(TxList,finalResp)

	w.WriteHeader(http.StatusNoContent) 
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
				C.CKA_KEY_TYPE:  C.CKK_AES,
				C.CKA_VALUE_LEN: 32,
				C.CKA_UNWRAP:false,
                C.CKA_WRAP: false,
                C.CKA_ENCRYPT: true,
                C.CKA_SIGN: true,
                C.CKA_VERIFY: true,
                C.CKA_DERIVE: true,
                C.CKA_IBM_USE_AS_DATA: true,
                C.CKA_EXTRACTABLE: false,
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

        batchSize := 50000
        startTime := time.Now()
        lastLogTime := startTime
        lastLogCount := 0
    
        for r := range results {
            _, err := stmt.Exec(r.KeyID, r.Key, r.Scheme)
            if err != nil {
                log.Printf("batchWriter: failed to insert key %s: %v", r.KeyID, err)
                continue
            }
    
            count++
    
            // Log every 50k keys
            if count%batchSize == 0 {
                now := time.Now()
                elapsed := now.Sub(lastLogTime).Seconds()
                totalElapsed := now.Sub(startTime).Seconds()
                batchProcessed := count - lastLogCount
                speed := float64(batchProcessed) / elapsed
                log.Printf("[batchWriter] Processed %d keys (batch %d), batch time %.2fs, batch speed %.2f keys/sec, total time %.2fs",
                    count, count/batchSize, elapsed, speed, totalElapsed)
                lastLogTime = now
                lastLogCount = count
            }
        }
	tx.Commit()
	*successCount = count
}

// **************************************************************************************************************
// **************************************************************************************************************
func EKMFImportkeys(doc OSODoc) error {
    // --- Decode base64 ---
    gzipBytes, err := base64.StdEncoding.DecodeString(doc.Content)
    if err != nil {
        return fmt.Errorf("invalid base64 for doc %s: %w", doc.ID, err)
    }

    // --- Ungzip ---
    reader, err := gzip.NewReader(bytes.NewReader(gzipBytes))
    if err != nil {
        return fmt.Errorf("invalid gzip for doc %s: %w", doc.ID, err)
    }
    defer reader.Close()

    // --- Decode JSON inside gzip ---
    var keys []InputKey
    if err := json.NewDecoder(reader).Decode(&keys); err != nil {
        return fmt.Errorf("invalid JSON inside doc %s: %w", doc.ID, err)
    }

    // --- Append keys thread-safely ---
    keyListMu.Lock()
    keyList = append(keyList, keys...)
    keyListMu.Unlock()

    log.Printf("Imported %d keys from document %s", len(keys), doc.ID)
    return nil
}



// **************************************************************************************************************
// **************************************************************************************************************
func EKMFGenRsaKeyPair(req OSODoc) error {
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
        return fmt.Errorf("Failed to generate RSA key pair: %v", err)
    }

    // Generate UUID key ID

	var meta Meta

    if req.Metadata != "" {
		if err := json.Unmarshal([]byte(req.Metadata), &meta);err != nil {
		return fmt.Errorf("Unable to get key id Invalid metadata JSON in EKMFGENRSAKEYPAIR message %w", err)
		}
    } 

    keyID := meta.KeyID
    if keyID == "" {
        return fmt.Errorf("metadata missing keyID")
    }

    _, err = db.Exec("INSERT INTO rsa_keys(key_id, private_key) VALUES(?, ?)", keyID, sk)
    if err != nil {
        return fmt.Errorf("Failed to store private key: %w", err)
    }
    log.Printf("Private key successfully stored for keyID=%s", keyID)

    // Convert public key to PEM (SPKI)
    var spki asn1.RawValue
    rest, err := asn1.Unmarshal(pk, &spki)
    if err != nil {
        return fmt.Errorf("Failed to parse SPKI DER: %v", err)
    }

    pemBlock := &pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: pk[:len(pk)-len(rest)],
    }
    publicPEM := string(pem.EncodeToMemory(pemBlock))

    metaResp := map[string]string{
	"type":   "EKMFRSAIMPORT",
	"keyid":  keyID,
	"source": "EKMF",
    }

    metaRespJSON, err := json.Marshal(metaResp)
    if err != nil {
    	return fmt.Errorf("failed to build metadata JSON: %w", err)
    }

    // --- Return OSODoc style JSON ---
    resp := OSODoc{
		ID:        req.ID,
    	Content:   publicPEM,
		Signature: "",
    	Metadata:  string(metaRespJSON), // still a string as you wanted
    }

    TxList = append(TxList, resp)

    return nil 
}

// **************************************************************************************************************
// **************************************************************************************************************
func BackendGetCompletedHandler(w http.ResponseWriter, r *http.Request) {

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(TxList)

    TxList = nil
}

// **************************************************************************************************************
// UPLOAD KEYS (gzip+base64 JSON array)
// **************************************************************************************************************
func FrontendUploadHandler(w http.ResponseWriter, r *http.Request) {

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

// **************************************************************************************************************
// **************************************************************************************************************
func FrontendGetEKMFMsgsHandler(w http.ResponseWriter, r *http.Request) {
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
	var docs []OSODoc

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
		meta := map[string]string{
			"type":   "EKMFKEYSIMPORT",
			"source": "EKMF",
		}

		metaJSON, err := json.Marshal(meta)
		if err != nil {
			http.Error(w, "Failed to build metadata", http.StatusInternalServerError)
			return
		}

		// create a document
		docs = append(docs, OSODoc{
			ID:        uuid.New().String(),
			Content:   b64Content,
			Signature: "",
			Metadata: string(metaJSON),
		})
	}

    cmds := GetAllEKMFCmd()

    for _, cmd := range cmds {
        doc, err := ProcessEKMFCmd(cmd)
        if err != nil {
            log.Printf("Failed: %v", err)
        } else  {
        	docs = append(docs, doc)
        }
    }

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(docs)
}


func GetAllEKMFCmd() []EKMFCmd {
    queueMutex.Lock()
    defer queueMutex.Unlock()

    if len(ekmfCmdQueue) == 0 {
        return nil
    }

    // Copy queue
    cmds := make([]EKMFCmd, len(ekmfCmdQueue))
    copy(cmds, ekmfCmdQueue)

    // Clear queue
    ekmfCmdQueue = nil

    return cmds
}

func ProcessEKMFCmd(cmd EKMFCmd) (OSODoc,error) {
    t, ok := cmd.Metadata["type"].(string)
    if !ok {
        return OSODoc{},fmt.Errorf("missing type")
    }

    switch t {
    case "EKMFGENRSAKEYPAIR":
    	return processGenRSAKeyPair(cmd)
    case "EKMFTKEY":
    	return processTransportKey(cmd)
    case "EKMFLIST":
    	return processListKeys(cmd)
     default:
        return OSODoc{}, fmt.Errorf("unknown type: %s", t)
    }
}

func processTransportKey(cmd EKMFCmd) (OSODoc, error) {
    // Make sure metadata contains "keyid"
    keyidVal, ok := cmd.Metadata["keyid"].(string)
    if !ok || keyidVal == "" {
        return OSODoc{},fmt.Errorf("EKMFTKEY cmd missing keyid in metadata")
    }

    // Make sure Content is not empty
    if cmd.Content == "" {
        return OSODoc{},fmt.Errorf("wrappedkey not provided")
    }

   return OSODoc{
        ID:        uuid.New().String(),
        Content:   cmd.Content,          // content comes from the cmd
        Signature: "",
        Metadata:  cmd.MetadataJSON(),   // metadata as-is
    }, nil

}
  
func processGenRSAKeyPair(cmd EKMFCmd) (OSODoc, error) {
    rsakeyid := fmt.Sprintf("rsa-%d", time.Now().UnixNano())

    meta := map[string]string{
        "type":   "EKMFGENRSAKEYPAIR",
        "source": "EKMF",
        "keyid":  rsakeyid,
    }

    metaJSON, err := json.Marshal(meta)
    if err != nil {
        return OSODoc{},err
    }

    return OSODoc{
        ID:        uuid.New().String(),
        Content:   "",
        Signature: "",
        Metadata:  string(metaJSON),
    }, nil
}

func processListKeys(cmd EKMFCmd) (OSODoc, error) {
    meta := map[string]string{
        "type":   "EKMFLIST",
        "source": "EKMF",
    }

    metaJSON, err := json.Marshal(meta)
    if err != nil {
        return OSODoc{},err
    }

    return OSODoc{
        ID:        uuid.New().String(),
        Content:   "",
        Signature: "",
        Metadata:  string(metaJSON),
    }, nil
}

func FrontendEKMFCmdHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "POST only", http.StatusMethodNotAllowed)
        return
    }

    var req struct {
        Content   string `json:"Content"`
        Signature string `json:"Signature"`
        Metadata  map[string]interface{} `json:"Metadata"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid JSON body", http.StatusBadRequest)
        return
    }

   // Metadata is already a map[string]interface{}
    meta := req.Metadata
    if meta == nil {
        http.Error(w, "Metadata missing", http.StatusBadRequest)
        return
    }

    // Validate "type"
    t, ok := meta["type"].(string)
    if !ok || t == "" {
        http.Error(w, "Metadata.type missing", http.StatusBadRequest)
        return
    }

    allowedTypes := map[string]bool{
        "EKMFGENRSAKEYPAIR": true,
        "EKMFTKEY": true,
        "EKMFLIST":   true,
    }

    if !allowedTypes[t] {
        http.Error(w, "Unknown metadata.type", http.StatusBadRequest)
        return
    }

    // Add source attribute
    meta["source"] = "EKMF"

    cmd := EKMFCmd{
        Content:   req.Content,
        Signature: req.Signature,
        Metadata:  meta,
    }

    // Store in global queue
    queueMutex.Lock()
    ekmfCmdQueue = append(ekmfCmdQueue, cmd)
    queueMutex.Unlock()

    w.Header().Set("Content-Type", "application/json")
    w.Write([]byte(`{"status":"queued"}`))
}