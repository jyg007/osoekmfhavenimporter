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
    "crypto/tls"
    "io"
)

// Define an EKMF import format for a key
type InputKey struct {
	ID   		string `json:"id"`
	WrappedKey 	string `json:"wrappedkey"`
	Csum 		string `json:"csum"`
}

// EKMF command - uuid to be generated in the FrontEnd after validation
type EKMFCmd struct {
    Content   string                 `json:"Content"`
    Signature string                 `json:"Signature"`
    Metadata  map[string]interface{} `json:"Metadata"`
}

type OSODoc struct {
	ID        string      `json:"id"`        // document index / uuid
	Content   string      `json:"content"`   
	Signature string      `json:"signature"` // empty for now
	Metadata  string       `json:"metadata"`  // static info
}

// Backend - Batch of keys to import into sqlite
type ProcessedKey struct {
	KeyID  string
	Key    []byte
	Scheme string
}

// Backend Batch of keys to process
type KeyBatch struct {
	Keys []InputKey
}

type ProcessResult struct {
	SuccessCount int      `json:"success_count"`
	FailedCount  int      `json:"failed_count"`
	FailedIDs    []string `json:"failed_ids"`
}

type Meta struct {
	Type  string `json:"type"`
	KeyID string `json:"keyid"`
}

var (
	ekmfCmdQueue 		[]EKMFCmd        // Frontend Queue 1 - EKMF cmsg picked from EKMFQ and used to create []OSOdoc 
    ekmfCmdQueueMutex   sync.Mutex

	keyList     		[]InputKey		 // FrontEnd & Backend Queue: Keys to import and bulked as EKMFKEYSIMPORT msgs
	keyListMu   		sync.Mutex

 	TxList      		[]OSODoc         // Backend OSO msgs queues for Output Bridge (stores results of EKMF commands)
	wrappingKey 		[]byte           // Backend - EKMF transort key set per OSO iteration for import
	
	db     		     	*sql.DB          // Backend - db 
	numAdapters 		int              // Backend - number of crypto adapters as defined by EP11_HSM_DOMAIN
	target      		ep11.Target_t    // Backend
    targets_single		[]ep11.Target_t  // Backend - ep11 target used for rotation [mono adapters]
    backendprocessed 	uint64           // Backend used by backend workers
)

type cmdConfig struct {
    allowed            bool
    requiresSignature  bool
}

var EKMFcommands = map[string]cmdConfig{
    "EKMFGENRSAKEYPAIR":     {allowed: true},
    "EKMFTKEY":              {allowed: true},
    "EKMFLIST":              {allowed: true},
    "EKMFKEYSIMPORT":        {allowed: true, requiresSignature: true},   // ed25519 sig, the ekmf admin signs the ekmf contents besides the mTLS authent
    "EKMFROTATE":            {allowed: true},
    "EKMFDELETE":            {allowed: true, requiresSignature: true},
    "EKMFACTIVATEROTATION":  {allowed: true},
}

// **************************************************************************************************************
// **************************************************************************************************************
// **************************************************************************************************************
// **************************************************************************************************************
func main() {
    mode := os.Getenv("mode")
    if mode == "" {
        log.Fatal("MODE environment variable not set (frontend or backend)")
    }

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

        dbPath := os.Getenv("DB_PATH")
		if dbPath == "" {
		    dbPath = "/data/keys.db"   // good default for containers
		}

		var err error
		db, err = sql.Open("sqlite3", dbPath)
		if err != nil {
		    panic(err)
		}

		// Close cleanly
		defer func() {
		    // 1. Force checkpoint so WAL is merged into keys.db
		    _, err := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE);`)
		    if err != nil {
		        log.Printf("checkpoint error: %v", err)
		    }

		    // 2. Switch back to DELETE mode so the -wal file disappears
		    _, err = db.Exec(`PRAGMA journal_mode = DELETE;`)
		    if err != nil {
		        log.Printf("journal mode reset error: %v", err)
		    }

		    err = db.Close()
		    if err != nil {
		        log.Printf("close error: %v", err)
		    }

		    log.Println("Database cleaned and closed.")
			}()
        
        // WAL mode (fast + safe for many inserts)
		_, err = db.Exec(`PRAGMA journal_mode = WAL;`)
		if err != nil {
		    log.Fatal(err)
		}

		// Much faster than FULL when importing thousands of keys
		_, err = db.Exec(`PRAGMA synchronous = NORMAL;`)
		if err != nil {
		    log.Fatal(err)
		}

		// Avoid disk-full errors caused by temp files
		_, err = db.Exec(`PRAGMA temp_store = MEMORY;`)
		if err != nil {
		    log.Fatal(err)
		}

		// Auto-shrink WAL regularly
		_, err = db.Exec(`PRAGMA wal_autocheckpoint = 1000;`)
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
    	// to_ekmf
        http.HandleFunc("/FrontendUploadEKMFMsgs", FrontendEKMFUploadHandler)
        // to_oso
        http.HandleFunc("/FrontendDownloadEKMFMsgs", FrontendDownloadEKMFMsgsHandler)

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
// Handler to be invoked by OSO plugin
// Turn received EKMF msgs from EKMFQ into OSO Docs
// Bulking of EKMF keys to import into potential smaller message [keys_per_doc parameter]
// **************************************************************************************************************
func FrontendDownloadEKMFMsgsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}

	var docs []OSODoc

	GetEKMFQMsgs()    // Next function

    ekmfCmdQueueMutex.Lock()
    if len(ekmfCmdQueue) != 0 {       
	    // Copy queue
	    cmds := make([]EKMFCmd, len(ekmfCmdQueue))
	    copy(cmds, ekmfCmdQueue)

    	// Clear queue
    	ekmfCmdQueue = nil
    	ekmfCmdQueueMutex.Unlock()

	    for _, cmd := range cmds {
	       // doc, err := ProcessEKMFCmd(cmd)
	        metadataJSON, err := cmd.MetadataJSON()
			if err != nil {
		    	log.Printf("EKMF Cmd error in metadataJSON: %v", err)
		    	continue
		    }
	        doc := OSODoc{
	     	   	ID:        uuid.New().String(),
		        Content:   cmd.Content,
	        	Signature: cmd.Signature,
	        	Metadata:	string(metadataJSON),
	        	//Metadata:  cmd.Metadata,
	   		}

	        if err != nil {
	            log.Printf("Failed: %v", err)
	        } else  {
	        	docs = append(docs, doc)
	        }
	    }
	} else {
    	ekmfCmdQueueMutex.Unlock()
	}

    //Creates EKMFKEYSIMPORT by bulking them using keysPerDoc params
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

// turn a json into a string
func (c EKMFCmd) MetadataJSON() (string, error) {
    b, err := json.Marshal(c.Metadata)
    if err != nil {
        return "", fmt.Errorf("failed to marshal metadata: %w", err)
    }
    return string(b), nil
}

//**************************************************************************************************
//**************************************************************************************************
// Retrieves queued EKMF cmdq from EKMFQ
//**************************************************************************************************
//**************************************************************************************************

func GetEKMFQMsgs() {
	client, queue, err := FrontendConnectEKMFQ()

	if err != nil {
		log.Printf("failed to connect EKMFQ: %v", err)
		return
	}
	// --- 6. Make GET request ---
	url := fmt.Sprintf("https://localhost:4433/payload/%s", queue)
	resp, err := client.Get(url)
	if err != nil {
		log.Printf("[GET EKFMQ] Connection error for queue: %v", err)
		return
	}	
	defer resp.Body.Close()

	// --- Decode JSON array directly from response body ---
	var cmds []EKMFCmd
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &cmds); err != nil {
		log.Printf("[GET EKMFQ] unable to marshall EKMF cmd %v", err)
		return
	}

	for _, cmd := range cmds {
		EKMFCmdValidation(cmd)   // Next function
	}
}

//*****************************************************************************************************
//  Add received EKMFQ EKMFmsgs into Frontend EKMFCmd Queue
//*****************************************************************************************************

func EKMFCmdValidation(req EKMFCmd)  {
	verifySignature := func(content string, signatureB64 string) error {

		envB64 := os.Getenv("ED25519_PUBLIC_KEY")
		derBytes, err := base64.StdEncoding.DecodeString(envB64)
		if err != nil {
		    log.Printf("Base64 decode failed: %v", err)
		    return err
		}

		pubKeyInterface, err := x509.ParsePKIXPublicKey(derBytes)
		if err != nil {
		    log.Printf("Parse public key failed: %v", err)
		    return err
		}

		edPubKey, ok := pubKeyInterface.(ed25519.PublicKey)
		if !ok {
		    log.Printf("Not an Ed25519 key")
		    return err
		}
	    // 5. Decode signature and verify
	    sig, _ := base64.StdEncoding.DecodeString(signatureB64)

	    if !ed25519.Verify(edPubKey, []byte(content), sig) {
	        log.Printf("signature invalid %s",content)
	        return fmt.Errorf("Invalid Signature")
	    }

	    return nil
	}

   // Metadata is already a map[string]interface{}
    meta := req.Metadata
    if meta == nil {
    	log.Printf("EKMF Cmd: Metadata missing")
        return
    }

    // Validate "type"
    t, ok := meta["type"].(string)
    if !ok || t == "" {
    	log.Printf("EKMF Cmd: Metadata type missing")
        return
    }

	cfg, exists := EKMFcommands[t]
	if !exists || !cfg.allowed {
	    log.Printf("EKMF Cmd: Not allowed metadata.type")
	    return
	}

	if cfg.requiresSignature {
        if req.Signature == "" {
	    	log.Printf("EKMF Cmd: Signature required for type %s",t)
	        return 
	    }

	    if err := verifySignature(req.Content, req.Signature); err != nil {
	        log.Printf("Invalid signature received for message type %s", t)
	        return 
	    }
	}

	// Import file are unzipped and ekmf keys to be reassembled later as small oso messages if necessary
    if (t == "EKMFKEYSIMPORT") {
		id, ok := req.Metadata["id"].(string)
	    if !ok ||  id == "" {
	        log.Printf("EKMFKEYSIMPORT id missing metadata")
	        return
	    }
	   	log.Printf("Processing EMKF key file upload ID: %s", id)


	    // Make sure Content is not empty
	    if req.Content == "" {
	        log.Printf("EKMFKEYSIMPORT %s No content provided",id)
	        return
	    }

		gzipBytes, err := base64.StdEncoding.DecodeString(req.Content)
		if err != nil {
			log.Printf("EKMFKEYSIMPORT %s base64 failure: %v", id,err)
			return
		}

		reader, err := gzip.NewReader(bytes.NewReader(gzipBytes))
		if err != nil {
			log.Printf("EKMFKEYSIMPORT %s gzip failure: %v", id,err)
			return
		}
		defer reader.Close()

		var keys []InputKey
		if err := json.NewDecoder(reader).Decode(&keys); err != nil {
			log.Printf("EKMF File ID %s : invalid JSON inside gzip", id)
			return
		}

		//Put in Import Queue 
		keyListMu.Lock()
		keyList = append(keyList, keys...)
		keyListMu.Unlock()
    } else {

    	switch t {
		  	case "EKMFGENRSAKEYPAIR":
		  	    rsakeyid := fmt.Sprintf("rsa-%d", time.Now().UnixNano())
		   		req.Metadata["keyid"] = rsakeyid
	  	    case "EKMFTKEY":
			    keyidVal, ok := req.Metadata["keyid"].(string)
			    if !ok || keyidVal == "" {
			        log.Printf("EKMFTKEY cmd missing keyid in metadata")
			    }

			    // Make sure Content is not empty
			    if req.Content == "" {
			        log.Printf("wrappedkey not provided")
			    }
		}

	    // Add source attribute
	    meta["source"] = "EKMF"

	    cmd := EKMFCmd{
	        Content:   req.Content,
	        Signature: req.Signature,
	        Metadata:  meta,
	    }

	    // Store in EKMF Cmd global queue
	    ekmfCmdQueueMutex.Lock()
	    ekmfCmdQueue = append(ekmfCmdQueue, cmd)
	    ekmfCmdQueueMutex.Unlock()    	
    }
}

//***************************************************************************************************************
// Connection to EKMFQ
//		Returns http.Client
//		connection is defined using environement variables: 
//			OSOQUEUE: logical name representing the OSO, for exemple OSO1, PRODOSO1, etc
//			CLIENTCERT, CLIENTKEY, CACERT: cert, key and ca cert for mTLS authentication with EKMFQ
//***************************************************************************************************************

func FrontendConnectEKMFQ() (*http.Client, string,error) {
	// --- 1. Get OSO queue ---
	queue := os.Getenv("OSOQUEUE")
	if queue == "" {
		return nil, "", fmt.Errorf("OSOQUEUE environment variable not set")
	}

	// --- 2. Get client cert, key, and CA ---
	clientCertB64 := os.Getenv("CLIENTCERT")
	clientKeyB64 := os.Getenv("CLIENTKEY")
	caCertB64 := os.Getenv("CACERT")

	if clientCertB64 == "" || clientKeyB64 == "" {
		return nil, "", fmt.Errorf("CLIENTCERT or CLIENTKEY environment variable not set")
	}

	// --- 3. Decode certs ---
	clientCertPEM, err := base64.StdEncoding.DecodeString(clientCertB64)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode CLIENTCERT: %w", err)
	}

	clientKeyPEM, err := base64.StdEncoding.DecodeString(clientKeyB64)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode CLIENTKEY: %w", err)
	}

	cert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		return nil, "", fmt.Errorf("invalid client certificate/key: %w", err)
	}

	// --- 4. CA pool (optional) ---
	var caCertPool *x509.CertPool
	if caCertB64 != "" {
		caCertPEM, err := base64.StdEncoding.DecodeString(caCertB64)
		if err != nil {
			return nil, "", fmt.Errorf("failed to decode CACERT: %w", err)
		}

		caCertPool = x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCertPEM) {
			return nil, "", fmt.Errorf("failed to append CA certificate")
		}
	}

	// --- 5. TLS config ---
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
		InsecureSkipVerify: true, // ⚠️ consider making this configurable
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return client, queue, nil
}

//***************************************************************************************************************
// Handler .  To be invoked by OSO plugin  to send OSOdocs to EKFMQ
//***************************************************************************************************************

func FrontendEKMFUploadHandler(w http.ResponseWriter, r *http.Request) {
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

	client, queue, err := FrontendConnectEKMFQ()

	if err != nil {
		log.Printf("failed to connect EKMFQ: %v", err)
		return
	} else {
		jsonData, err := json.Marshal(payload)
		if err != nil {
		    log.Printf("[POST EKFMQ] JSON marshal error: %v", err)
		    return
		}
		url := fmt.Sprintf("https://localhost:4433/response/%s", queue)
		resp, err := client.Post(url, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
		    log.Printf("[POST EKFMQ] Connection error: %v", err)
		    return
		}
		defer resp.Body.Close()
	}
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
// API handler - To be called from OSO plugin to upload EKMF OSO doc
//     source="EKMF"  is not checked, assume to be verified by the plugin
//
//  All actions will be executed in the upload steps when Input Bridge connects the plugin
//  Results will be retrieved in the download handler (last function)
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
    case "EKMFDELETE":
        if err := KeysDeletion(payload); err != nil {
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

func KeysDeletion(req OSODoc) error {

    // ---- Parse list of key IDs ----
    var keyIDs []string
    if err := json.Unmarshal([]byte(req.Content), &keyIDs); err != nil {
        return fmt.Errorf("invalid key list in content: %w", err)
    }

    if len(keyIDs) == 0 {
        return fmt.Errorf("empty key list")
    }

    // ---- Start transaction ----
    tx, err := db.Begin()
    if err != nil {
        return fmt.Errorf("failed to begin transaction: %w", err)
    }

    // ---- Response array ----
    type DeleteResult struct {
        KeyID  string `json:"key_id"`
        Status string `json:"status"`
    }

    results := []DeleteResult{}

    // ---- Delete keys one by one ----
    for _, id := range keyIDs {
        res, err := tx.Exec("DELETE FROM keys WHERE key_id = ?", id)
        if err != nil {
            results = append(results, DeleteResult{
                KeyID:  id,
                Status: "failed",
            })
            continue
        }

        rows, err := res.RowsAffected()
        if err != nil || rows == 0 {
            results = append(results, DeleteResult{
                KeyID:  id,
                Status: "failed",
            })
            continue
        }

        results = append(results, DeleteResult{
            KeyID:  id,
            Status: "deleted",
        })
        log.Printf("[KeysDeletion] %s deleted", id)
    }

    // ---- Commit transaction ----
    if err := tx.Commit(); err != nil {
        return fmt.Errorf("failed to commit deletion: %w", err)
    }

  

    // ---- Convert results to JSON ----
    contentJSON, err := json.Marshal(results)
    if err != nil {
        return fmt.Errorf("failed to marshal response content: %w", err)
    }

    // ---- Metadata ----
    metaResp := map[string]string{
        "type":   "EKMFDELETEKEYS",
        "source": "EKMF",
    }

    metaRespJSON, err := json.Marshal(metaResp)
    if err != nil {
        return fmt.Errorf("failed to build metadata JSON: %w", err)
    }

    // ---- OSODoc response ----
    resp := OSODoc{
        ID:        req.ID,
        Content:   string(contentJSON),
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


type Job struct {
    KeyID string
    Key   []byte
    TargetIndex int
}

type Result struct {
    KeyID string
    Value string
}

type Processor func(j Job) (Result, error)

// --- dedicated SQLite update worker ---
type UpdateJob struct {
	KeyID  string
	NewKey []byte
}

// Update worker thread to process sqlite update
func updateWorker(db *sql.DB, updateChan <-chan UpdateJob, done chan struct{}) {
	const batchSize = 50000

	tx, err := db.Begin()
	if err != nil {
		log.Fatalf("updateWorker: begin transaction failed: %v", err)
	}

	stmt, err := tx.Prepare(`UPDATE keys SET new_key = ? WHERE key_id = ?`)
	if err != nil {
		log.Fatalf("updateWorker: prepare failed: %v", err)
	}
	defer stmt.Close()

	count := 0

	for u := range updateChan {
		_, err := stmt.Exec(u.NewKey, u.KeyID)
		if err != nil {
			log.Printf("updateWorker: failed to update new_key for %s: %v", u.KeyID, err)
			continue
		}

		count++

		// commit and checkpoint every batch
		if count%batchSize == 0 {
			if err := tx.Commit(); err != nil {
				log.Printf("updateWorker: commit failed: %v", err)
			}
			if _, err := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE);`); err != nil {
				log.Printf("updateWorker: checkpoint failed: %v", err)
			}

			tx, err = db.Begin()
			if err != nil {
				log.Fatalf("updateWorker: new transaction failed: %v", err)
			}
			stmt, err = tx.Prepare(`UPDATE keys SET new_key = ? WHERE key_id = ?`)
			if err != nil {
				log.Fatalf("updateWorker: prepare failed: %v", err)
			}
		}
	}

	// commit any remaining updates
	if err := tx.Commit(); err != nil {
		log.Printf("updateWorker: final commit failed: %v", err)
	}

 	// final checkpoint
    _, _ = db.Exec(`PRAGMA wal_checkpoint(TRUNCATE);`)
	// signal done
	close(done)
}

// worker jobs for processing keys as defined in Processor function
func worker2(jobs <-chan Job, results chan<- Result, wg *sync.WaitGroup, p Processor) {
    defer wg.Done()

    for j := range jobs {

        r, err := p(j)
        if err != nil {
            log.Printf("processing failed for key %s: %v", j.KeyID, err)
            continue
        }

        results <- r
        atomic.AddUint64(&backendprocessed, 1)
    }
}

var targets []ep11.Target_t

//CENC0 Checksum processor
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
    }, nil
}

// mek rotation processor
func processRotate(j Job,updateChan chan<- UpdateJob) (Result, error) {
	t := targets[j.TargetIndex]
    // --- re-encipher the key ---
    reenciphered, err := ep11.Reencipher(t, j.Key)
    if err != nil {
        log.Printf("reencipher failed for key %s: %v", j.KeyID, err)
        return Result{
        	KeyID: j.KeyID,
        	Value: "failed", // can return cenc0 or other metadata
     	}, nil
    }

    // --- store in SQLite in new_key column ---
	updateChan <- UpdateJob{
		KeyID:  j.KeyID,
		NewKey: reenciphered,
	}

    return Result{
        KeyID: j.KeyID,
        Value: "success", // can return cenc0 or other metadata
    }, nil
}

func ProcessEKMFMessage(doc OSODoc, Type string) error {
	workers := 8 * numAdapters

	jobs := make(chan Job, 20000)
	results := make(chan Result, 20000)

	var processor Processor

	// --- Dedicated SQLite update worker ---
	updateChan := make(chan UpdateJob, 1000)
	updateDone := make(chan struct{})

	// --- Select operation ---
	switch Type {
	case "EKMFLIST":
		processor = processCENC0
		targets = []ep11.Target_t{target}

	case "EKMFROTATE":
		processor = func(j Job) (Result, error) {
			return processRotate(j, updateChan)
		}
		targets = targets_single

	default:
		return fmt.Errorf("unsupported EKMF message type: %s", Type)
	}

	// --- start SQLite writer ---
    go updateWorker(db, updateChan, updateDone)
	// --- performance timer ---
	backendprocessed = 0
	start := time.Now()
	done := make(chan struct{})

	// --- per-second speed logger ---
	go func() {
	    ticker := time.NewTicker(1 * time.Second)
	    defer ticker.Stop()

	    for {
	        select {
	        case <-ticker.C:
	            n := atomic.LoadUint64(&backendprocessed)
	            elapsed := time.Since(start).Seconds()
	            if elapsed > 0 {
	                log.Printf("[EKMF %s] processed=%d speed=%.0f keys/sec", Type, n, float64(n)/elapsed)
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

    // --- result collector (this was missing) ---
    var resultList []Result
    var collectorWG sync.WaitGroup
    collectorWG.Add(1)

    go func() {
        defer collectorWG.Done()
        for r := range results {
            resultList = append(resultList, r)
        }
    }()

	 // --- fetch rows ---
    rows, err := db.Query(`
        SELECT key_id, key
        FROM keys
        WHERE scheme='SEED' AND (new_key IS NULL OR ? = 'EKMFLIST')
    `, Type)

	if err != nil {
		return err
	}
	defer rows.Close()

	// --- assign targets round-robin ---
	if len(targets) == 1 {
		for rows.Next() {
			var j Job
			if err := rows.Scan(&j.KeyID, &j.Key); err != nil {
				return err
			}
			j.TargetIndex = 0
			jobs <- j
		}
	} else {
		targetIndex := 0
		for rows.Next() {
			var j Job
			if err := rows.Scan(&j.KeyID, &j.Key); err != nil {
				return err
			}
			j.TargetIndex = targetIndex
			jobs <- j
			
			targetIndex++
            if targetIndex == len(targets) {
                targetIndex = 0
            }
		}
	}

	close(jobs)
	wg.Wait()         // wait for all workers to finish
	close(results)
	collectorWG.Wait()

	// --- wait for SQLite update ---
	close(updateChan)
	<-updateDone

	// stop ticker
	close(done)

	// --- prepare final message ---
	jsonArray := make([]map[string]string, 0, len(resultList))
	for _, r := range resultList {
	    jsonArray = append(jsonArray, map[string]string{
	        "KeyID": r.KeyID,
	        "Value": r.Value,
	    })
	}

	finalJSON, err := json.Marshal(jsonArray)
	if err != nil {
	    log.Printf("failed to marshal results: %v", err)
	    return err
	} else {
	    // reuse the incoming doc
	    doc.Content = string(finalJSON)
	    metaResp := map[string]string{
			"type":   Type,
			"source": "EKMF",
    	}

		metaBytes, err := json.Marshal(metaResp)
		if err != nil {
		    return fmt.Errorf("failed to marshal metadata: %w", err)
		}
		doc.Metadata = string(metaBytes)
	    
	    TxList = append(TxList, doc)
	}

	total := atomic.LoadUint64(&backendprocessed)
	elapsed := time.Since(start).Seconds()

	log.Printf("[EKMF] DONE type=%s total=%d time=%.2fs speed=%.0f keys/sec workers=%d",
		Type,
		total,
		elapsed,
		float64(total)/elapsed,
		workers,
	)

	return nil
}

// **************************************************************************************************************
// Launch parallel keys import processing if transport key was not forgotten
// **************************************************************************************************************
func BackendProcessHandler(w http.ResponseWriter, r *http.Request) {
	
	batchSize := 100000
	fmt.Sscanf(r.URL.Query().Get("batch_size"), "%d", &batchSize)
	if batchSize <= 0 {
		batchSize = 100000
	}

	keyListMu.Lock()    // not really necessary for backend as single thread
	if len(keyList) == 0 {
		keyListMu.Unlock()
		w.WriteHeader(http.StatusNoContent) 
		return
	}

	if wrappingKey == nil {
		keyList = nil
		keyListMu.Unlock()
		log.Println("[BackendProcess] No transport key set. Aborting import process.")
		http.Error(w, "No transport key set", http.StatusBadRequest)		
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
	log.Printf("Starting %d workers", numWorkers)

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
            "source": 	"EKMF",   // only if you also want the same field as Python
            "type": 	"EKMFIMPORTRESULT",
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

//***********************************************************************************************************************
// AES Unwrap WORKERs
//***********************************************************************************************************************
func worker(jobs <-chan KeyBatch, results chan<- ProcessedKey, failed chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()

	for batch := range jobs {
		for _, k := range batch.Keys {

			data, err := hex.DecodeString(k.WrappedKey)
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

//***********************************************************************************************************
// SQLITE WRITER
//***********************************************************************************************************
func batchWriter(results <-chan ProcessedKey, wg *sync.WaitGroup, successCount *int) {
	defer wg.Done()

	tx, err := db.Begin()
	if err != nil {
		log.Printf("batchWriter: begin transaction failed: %v", err)
		return
	}

	stmt, err := tx.Prepare("INSERT OR REPLACE INTO keys(key_id,key,scheme) VALUES(?,?,?)")
	if err != nil {
		log.Printf("batchWriter: prepare failed: %v", err)
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

		// --- checkpoint every batchSize keys ---
		if count%batchSize == 0 {
			// Commit current transaction to reduce WAL growth
			if err := tx.Commit(); err != nil {
				log.Printf("batchWriter: commit failed: %v", err)
			}

			// WAL checkpoint
			if _, err := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE);`); err != nil {
				log.Printf("batchWriter: checkpoint failed: %v", err)
			}

			// Start a new transaction for the next batch
			tx, err = db.Begin()
			if err != nil {
				log.Printf("batchWriter: new transaction failed: %v", err)
				return
			}
			stmt, err = tx.Prepare("INSERT OR REPLACE INTO keys(key_id,key,scheme) VALUES(?,?,?)")
			if err != nil {
				log.Printf("batchWriter: prepare failed: %v", err)
				return
			}

			// Log progress
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

	// Commit any remaining keys
	if err := tx.Commit(); err != nil {
		log.Printf("batchWriter: final commit failed: %v", err)
	}

	*successCount = count
}

// **************************************************************************************************************
// Read import files EKMF Message and appends all keys in keyList queue for final processing
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
// API Handler.
//		Just return the results of all EKMF commands
// **************************************************************************************************************
func BackendGetEKMFMsgsHandler(w http.ResponseWriter, r *http.Request) {

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(TxList)

    TxList = nil
}