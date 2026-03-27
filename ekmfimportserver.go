package main

/*
#cgo LDFLAGS: -lep11
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki
#include <stdint.h>
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
     "sync/atomic"
    "crypto/ed25519"
    "crypto/x509"
    "strings"
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
	numAdapters 		int
	wrappingKey 		[]byte
	keyList     		[]InputKey
	keyListMu   		sync.Mutex
 	TxList      		[]OSODoc
	ekmfCmdQueue 		[]EKMFCmd
    ekmfCmdQueueMutex   sync.Mutex
    processed 			uint64
    targets_single		[]ep11.Target_t  //for rotation
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
    	hsmTargets := strings.Fields(hsmTarget)
        for _, slotID := range hsmTargets {
	        t:= ep11.HsmInitNew(slotID)
	        targets_single = append(targets_single, t)
    	}

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
        defer func() {
	        // 1. Force a checkpoint to move data to the main .db file
    	    // 2. Change mode to DELETE to remove the -wal file
        	_, _ = db.Exec("PRAGMA journal_mode = DELETE;")
        	db.Close()
        	log.Println("Database cleaned and closed.")
    	}()
        
           // 2️⃣ Set safe PRAGMAs immediately
    	_, err = db.Exec(`PRAGMA journal_mode = WAL;`)
    	if err != nil {
        	log.Fatal(err)
    	}

    	_, err = db.Exec(`PRAGMA synchronous = FULL;`)
    	if err != nil {
        	log.Fatal(err)
    	}

        // Reset tables for backend
 		// _, err = db.Exec(`DROP TABLE IF EXISTS keys;
		_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS keys (
		    key_id   TEXT PRIMARY KEY,
		    key      BLOB NOT NULL,
		    new_key  BLOB,       -- used only during rotation
		    scheme   TEXT NOT NULL
		);
		`)
		if err != nil {
		    panic(err)
		}
        
        _, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS rsa_keys (
            key_id TEXT PRIMARY KEY,
            private_key BLOB NOT NULL
        );
        VACUUM;`)
        if err != nil {
            log.Fatal(err)
        }

        // Backend-specific handlers
        // To_EKMF
		http.HandleFunc("/BackendPostEKMFMsg", BackendPostEKMFMsgsHandler)
        http.HandleFunc("/BackendEKMFProcess", BackendProcessHandler)
        // to_oso
        http.HandleFunc("/BackendGetEKMFMsgs", BackendGetEKMFMsgsHandler)

        fmt.Println("Backend server listening on :9080")
        log.Fatal(http.ListenAndServe(":9080", nil))
    }

    if mode == "frontend" {
    	//from external
        http.HandleFunc("/FrontendEKMFCmd", FrontendEKMFCmdHandler)
        // to_oso
        http.HandleFunc("/FrontendGetEKMFMsgs", FrontendGetEKMFMsgsHandler)

        fmt.Println("Frontend server listening on :8080")
        log.Fatal(http.ListenAndServe(":8080", nil))
    }
}


//***************************************************************************************************************
//***************************************************************************************************************
//#######  ######   #######  #     #  #######  #######  #     #  ######   
//#        #     #  #     #  ##    #     #     #        ##    #  #     #  
//#        #     #  #     #  # #   #     #     #        # #   #  #     #  
//#####    ######   #     #  #  #  #     #     #####    #  #  #  #     #  
//#        #   #    #     #  #   # #     #     #        #   # #  #     #  
//#        #    #   #     #  #    ##     #     #        #    ##  #     #  
//#        #     #  #######  #     #     #     #######  #     #  ######   
//***************************************************************************************************************
// **************************************************************************************************************
// Get tge results of all EKMF messages uploaded to the frontend
// **************************************************************************************************************
func FrontendGetEKMFMsgsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}

	var docs []OSODoc
	// Process Commands Msg
    cmds := GetAllEKMFCmd()

    for _, cmd := range cmds {
        doc, err := ProcessEKMFCmd(cmd)
        if err != nil {
            log.Printf("Failed: %v", err)
        } else  {
        	docs = append(docs, doc)
        }
    }

    //Digest imported keys via EKMFKEYSIMPORT msg
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(docs)
}

func GetAllEKMFCmd() []EKMFCmd {
    ekmfCmdQueueMutex.Lock()
    defer ekmfCmdQueueMutex.Unlock()

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
    	return processKMSCommand(cmd,t)
    case "EKMFROTATE":
    	return processKMSCommand(cmd,t)
    case "EKMFACTIVATEROTATION":
    	return processKMSCommand(cmd,t)
    default:
        return OSODoc{}, fmt.Errorf("Process EKMF Cmd - Unknown type: %s", t)
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

func processKMSCommand(cmd EKMFCmd, msgType string) (OSODoc, error) {
    meta := map[string]string{
        "type":   msgType,
        "source": "EKMF",
    }

    metaJSON, err := json.Marshal(meta)
    if err != nil {
        return OSODoc{}, err
    }

    return OSODoc{
        ID:        uuid.New().String(),
        Content:   "",
        Signature: "",
        Metadata:  string(metaJSON),
    }, nil
}


func processKeysImport(cmd EKMFCmd) error {
	id, ok := cmd.Metadata["id"].(string)
    if !ok ||  id == "" {
        return fmt.Errorf("id missing metadata")
    }
   	log.Printf("Processing EMKF key file upload ID: %s", id)


    // Make sure Content is not empty
    if cmd.Content == "" {
        return fmt.Errorf("no content provided")
    }

	gzipBytes, err := base64.StdEncoding.DecodeString(cmd.Content)
	if err != nil {
		return err
	}

	reader, err := gzip.NewReader(bytes.NewReader(gzipBytes))
	if err != nil {
		return err
	}
	defer reader.Close()

	var keys []InputKey
	if err := json.NewDecoder(reader).Decode(&keys); err != nil {
		return fmt.Errorf("EKMF File ID %s : invalid JSON inside gzip", id)
	}

	keyListMu.Lock()
	keyList = append(keyList, keys...)
	keyListMu.Unlock()

	return nil
}


//**************************************************************************************************
//**************************************************************************************************
//  API to interact with EKMF addon and submit commands
//**************************************************************************************************
//**************************************************************************************************

func FrontendEKMFCmdHandler(w http.ResponseWriter, r *http.Request) {

	verifySignature := func(content string, signatureB64 string) error {

		envB64 := os.Getenv("ED25519_PUBLIC_KEY")
		derBytes, err := base64.StdEncoding.DecodeString(envB64)
		if err != nil {
		    log.Fatalf("Base64 decode failed: %v", err)
		}

		pubKeyInterface, err := x509.ParsePKIXPublicKey(derBytes)
		if err != nil {
		    log.Fatalf("Parse public key failed: %v", err)
		}

		edPubKey, ok := pubKeyInterface.(ed25519.PublicKey)
		if !ok {
		    log.Fatalf("Not an Ed25519 key")
		}
	    // 5. Decode signature and verify
	    sig, _ := base64.StdEncoding.DecodeString(signatureB64)

	    if !ed25519.Verify(edPubKey, []byte(content), sig) {
	        return fmt.Errorf("signature invalid")
	    }

	    return nil
	}


    if r.Method != http.MethodPost {
        http.Error(w, "POST only", http.StatusMethodNotAllowed)
        return
    }

    var req EKMFCmd;

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Req Invalid JSON body", http.StatusBadRequest)
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
        "EKMFKEYSIMPORT":   true,
        "EKMFROTATE":   true,
        "EKMFACTIVATEROTATION":   true,
    }

    if !allowedTypes[t] {
        http.Error(w, "Not allowed metadata.type", http.StatusBadRequest)
        return
    }

	var commandsRequiringSignature = map[string]bool{
	    "EKMFKEYSIMPORT": true,
	}

	// If this command requires a signature → verify it
	if commandsRequiringSignature[t] {
	    if req.Signature == "" {
	        http.Error(w, "Signature required for this command", http.StatusUnauthorized)
	        return
	    }

	    if err := verifySignature(req.Content, req.Signature); err != nil {
	        log.Printf("Invalid signature received for message type %s", t)
            http.Error(w, fmt.Sprintf("Signature verification failed: %v", err), http.StatusUnauthorized)
	        return
	    }
	}

    if (t == "EKMFKEYSIMPORT") {
    	// Keys upload populates immediately the internal queue list
		err := processKeysImport(req)
		if err != nil {
        	http.Error(w, "Error processing importfile", http.StatusBadRequest)
        	return
    	}
    } else {
	    // Add source attribute
	    meta["source"] = "EKMF"

	    cmd := EKMFCmd{
	        Content:   req.Content,
	        Signature: req.Signature,
	        Metadata:  meta,
	    }

	    // Store in global queue
	    ekmfCmdQueueMutex.Lock()
	    ekmfCmdQueue = append(ekmfCmdQueue, cmd)
	    ekmfCmdQueueMutex.Unlock()    	
    }

    w.Header().Set("Content-Type", "application/json")
    w.Write([]byte(`{"status":"queued"}`))
}


//***************************************************************************************************************
//***************************************************************************************************************
// #####      #      #####   #    #  #######  #     #  ######   
// #    #    # #    #     #  #   #   #        ##    #  #     #  
// #     #   #   #   #        #  #    #        # #   #  #     #  
// ######   #     #  #        ###     #####    #  #  #  #     #  
// #     #  #######  #        #  #    #        #   # #  #     #  
// #     #  #     #  #     #  #   #   #        #    ##  #     #  
// ######   #     #   #####   #    #  #######  #     #  ######   
//***************************************************************************************************************
//***************************************************************************************************************

//***************************************************************************************************************
// Uploads EKMF from OSO
//***************************************************************************************************************

func BackendPostEKMFMsgsHandler(w http.ResponseWriter, r *http.Request) {
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
         if err := ProcessEKMFMessage(payload,meta.Type); err != nil {
        	http.Error(w, err.Error(), http.StatusBadRequest)
        	return
    	}
  	case "EKMFROTATE":
        if err := ProcessEKMFMessage(payload,meta.Type); err != nil {
        	http.Error(w, err.Error(), http.StatusBadRequest)
        	return
    	}
    case "EKMFACTIVATEROTATION":
        if err := ActivateRotation(payload); err != nil {
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

func ActivateRotation(req OSODoc) error {
    // --- Swap rotated keys into the main column ---
    tx, err := db.Begin()
    if err != nil {
        return fmt.Errorf("failed to begin transaction: %w", err)
    }

    // 1. Replace main key with the rotated key
    _, err = tx.Exec(`UPDATE keys SET key = new_key WHERE new_key IS NOT NULL`)
    if err != nil {
        tx.Rollback()
        return fmt.Errorf("failed to update key with new_key: %w", err)
    }

    // 2. Clear the new_key column
    _, err = tx.Exec(`UPDATE keys SET new_key = NULL WHERE new_key IS NOT NULL`)
    if err != nil {
        tx.Rollback()
        return fmt.Errorf("failed to clear new_key column: %w", err)
    }

    // Commit transaction
    if err := tx.Commit(); err != nil {
        return fmt.Errorf("failed to commit rotation: %w", err)
    }

    log.Println("[ActivateRotation] Key rotation committed successfully.")

	metaResp := map[string]string{
		"type":   "EKMFACTIVATEROTATION",
		"source": "EKMF",
    }

    metaRespJSON, err := json.Marshal(metaResp)
    if err != nil {
    	return fmt.Errorf("failed to build metadata JSON: %w", err)
    }

    // --- Return OSODoc style JSON ---
    resp := OSODoc{
		ID:        req.ID,
    	Content:   "success",
		Signature: "",
    	Metadata:  string(metaRespJSON), // still a string as you wanted
    }

    TxList = append(TxList, resp)

    return nil
}

type Operation int

const (
    OpCENC0 Operation = iota
    OpRotate
    OpActivateRotate
)

type Job struct {
    KeyID string
    Key   []byte
    TargetIndex int
    Op    Operation
}

type Result struct {
    KeyID string
    Value string
    Op    Operation
}

type Processor func(j Job) (Result, error)

func worker2(jobs <-chan Job, results chan<- Result, wg *sync.WaitGroup, p Processor) {
    defer wg.Done()

    for j := range jobs {

        r, err := p(j)
        if err != nil {
            log.Printf("processing failed for key %s: %v", j.KeyID, err)
            continue
        }

        results <- r
        atomic.AddUint64(&processed, 1)
    }
}


var targets []ep11.Target_t
func processCENC0(j Job) (Result, error) {
    t := targets[j.TargetIndex]
    // 16-byte zero block (AES block size)
    zeroBlock := make([]byte, 16)

    // Encrypt zero block using AES-ECB
    cipher, err := ep11.EncryptSingle(
        t,
        ep11.Mech(C.CKM_AES_ECB, nil),
        j.Key,
        zeroBlock,
    )
    if err != nil {
        log.Printf("Encryption failed: %v", err)
    }
    
    return Result{
        KeyID: j.KeyID,
        Value: hex.EncodeToString(cipher[:3]),
        Op:   OpCENC0,
    }, nil
}

func processRotate(j Job) (Result, error) {
	t := targets[j.TargetIndex]
    // --- re-encipher the key ---
    reenciphered, err := ep11.Reencipher(t, j.Key)
    if err != nil {
        log.Printf("reencipher failed for key %s: %v", j.KeyID, err)
        return Result{
        	KeyID: j.KeyID,
        	Value: "failed", // can return cenc0 or other metadata
        	Op:    OpRotate,
    	}, nil
    }

    // --- store in SQLite in new_key column ---
    _, err = db.Exec(`UPDATE keys SET new_key = ? WHERE key_id = ?`, reenciphered, j.KeyID)
    if err != nil {
    	log.Printf("failed to update new_key for %s: %w", j.KeyID, err)
    	return Result{
        	KeyID: j.KeyID,
        	Value: "failed", // can return cenc0 or other metadata
        	Op:    OpRotate,
    	}, nil
    }

    return Result{
        KeyID: j.KeyID,
        Value: "success", // can return cenc0 or other metadata
        Op:    OpRotate,
    }, nil
}

func ProcessEKMFMessage(doc OSODoc,  Type string) error {

    workers := 8 * numAdapters

    jobs := make(chan Job, 20000)
    results := make(chan Result, 20000)

    var processor Processor

    // --- Select operation ---
    switch Type {

    case "EKMFLIST":
        processor = processCENC0
        targets = []ep11.Target_t{ target } 

    case "EKMFROTATE":
        processor = processRotate
       	targets = targets_single

    default:
        return fmt.Errorf("unsupported EKMF message type: %s", Type)
    }

    // --- performance timer ---
    processed = 0
    start := time.Now()

    done := make(chan struct{})

    go func() {
        ticker := time.NewTicker(1 * time.Second)
        defer ticker.Stop()

        for {
            select {
            case <-ticker.C:
                n := atomic.LoadUint64(&processed)
                elapsed := time.Since(start).Seconds()
                if elapsed > 0 {
                    log.Printf("[EKMF] processed=%d speed=%.0f keys/sec", n, float64(n)/elapsed)
                }
            case <-done:
                return
            }
        }
    }()

    // --- start workers ---
    var wg sync.WaitGroup
    for i := 0; i < workers; i++ {
        wg.Add(1)
        go worker2(jobs, results, &wg, processor)
    }

    // --- result collector ---
    var resultList []Result
    var collectorWG sync.WaitGroup
    collectorWG.Add(1)

    go func() {
        defer collectorWG.Done()
        for r := range results {
            resultList = append(resultList, r)
        }
    }()

	var rows *sql.Rows
	var err error
    if Type == "EKMFROTATE" {
    rows, err = db.Query(`
        SELECT key_id, key
        FROM keys
        WHERE scheme='SEED'
        AND new_key IS NULL
    `)
	} else {
    rows, err = db.Query(`
        SELECT key_id, key
        FROM keys
        WHERE scheme='SEED'
    `)
}
    if err != nil {
        return err
    }
    defer rows.Close()

    for rows.Next() {
        var j Job
        if err := rows.Scan(&j.KeyID, &j.Key); err != nil {
            return err
        }
 		// One job per target
        for i := range targets {
        	j.TargetIndex = i
            jobs <- j
            }
        //j.Op = op
        //jobs <- j
    }

    close(jobs)
    wg.Wait()
    close(results)
    collectorWG.Wait()
    close(done)

    total := atomic.LoadUint64(&processed)
    elapsed := time.Since(start).Seconds()

    log.Printf("[EKMF] DONE type=%s total=%d time=%.2fs speed=%.0f keys/sec workers=%d",
	    Type,        // <-- add the type here
	    total,
	    elapsed,
	    float64(total)/elapsed,
	    workers,
	)

    // --- metadata ---
    metaResp := map[string]string{
        "type":   Type,
        "source": "EKMF",
    }

    metaRespJSON, err := json.Marshal(metaResp)
    if err != nil {
        return err
    }

    contentJSON, err := json.Marshal(resultList)
    if err != nil {
        return err
    }

    resp := OSODoc{
        ID:        doc.ID,
        Content:   string(contentJSON),
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
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("No transport keys set"))
		log.Println("[BackendProcess] No transport key set")
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
func BackendGetEKMFMsgsHandler(w http.ResponseWriter, r *http.Request) {

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(TxList)

    TxList = nil
}
