package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"bytes"
)

// ------------------------------------------------------------
// Objects
// ------------------------------------------------------------

type Payload struct {
	Content   string `json:"content"`
	Signature string `json:"signature"`
	Metadata  json.RawMessage  `json:"metadata"`
}

type Response struct {
	ID        string `json:"id"`
	Content   string `json:"content"`
	Signature string `json:"signature"`
	Metadata  string `json:"metadata"`
}

// ------------------------------------------------------------
// Payload queue
// ------------------------------------------------------------

type PayloadQueue struct {
	mu    sync.Mutex
	items []Payload
}

func (q *PayloadQueue) Add(p Payload) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.items = append(q.items, p)
}

func (q *PayloadQueue) GetAllAndClear() []Payload {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := q.items
	q.items = nil // clear the queue
	return out
}

// ------------------------------------------------------------
// Response queue
// ------------------------------------------------------------

type ResponseQueue struct {
	mu    sync.Mutex
	items []Response
}

func (q *ResponseQueue) Add(r Response) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.items = append(q.items, r)
}

func (q *ResponseQueue) GetAllAndClear() []Response {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := q.items
	q.items = nil
	return out
}

// ------------------------------------------------------------
// Queue managers (independent)
// ------------------------------------------------------------
type PayloadManager struct {
	mu         sync.RWMutex
	authorized map[string]bool
	queues     map[string]*PayloadQueue
}

func NewPayloadManager() *PayloadManager {
	return &PayloadManager{
		authorized: loadQueuesFromEnv(),
		queues:     make(map[string]*PayloadQueue),
	}
}

func (pm *PayloadManager) GetQueue(name string) (*PayloadQueue, bool) {
	pm.mu.RLock()
	authorized := pm.authorized[name]
	pm.mu.RUnlock()

	if !authorized {
		return nil, false
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	q, exists := pm.queues[name]
	if !exists {
		q = &PayloadQueue{}
		pm.queues[name] = q
	}

	return q, true
}


type ResponseManager struct {
	mu         sync.RWMutex
	authorized map[string]bool
	queues     map[string]*ResponseQueue
}

func NewResponseManager() *ResponseManager {
	return &ResponseManager{
		authorized: loadQueuesFromEnv(),
		queues:     make(map[string]*ResponseQueue),
	}
}

func (rm *ResponseManager) GetQueue(name string) (*ResponseQueue, bool) {
	rm.mu.RLock()
	authorized := rm.authorized[name]
	rm.mu.RUnlock()

	if !authorized {
		return nil, false
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()

	q, exists := rm.queues[name]
	if !exists {
		q = &ResponseQueue{}
		rm.queues[name] = q
	}

	return q, true
}

var payloadManager = NewPayloadManager()
var responseManager = NewResponseManager()

// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------

func extractQueueName(path string) (string, bool) {
	parts := strings.Split(path, "/")
	if len(parts) < 3 {
		return "", false
	}
	return parts[2], true
}

// ------------------------------------------------------------
// Handlers
// ------------------------------------------------------------

// Helper to safely truncate long strings for logging
func truncateForLog(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "...(truncated)"
}

// Compact and truncate JSON for logging
func compactTruncateJSON(data []byte, max int) string {
	if len(data) == 0 {
		return ""
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, data); err != nil {
		// fallback: just truncate the raw data if JSON is invalid
		return truncateForLog(string(data), max)
	}
	return truncateForLog(buf.String(), max)
}

// ------------------------------------------------------------
// POST /payload/<queue>
func postPayload(w http.ResponseWriter, r *http.Request) {
	queueName, ok := extractQueueName(r.URL.Path)
	if !ok {
		log.Printf("[POST /payload] Invalid URL: %s", r.URL.Path)
		http.Error(w, "invalid URL", http.StatusBadRequest)
		return
	}

	queue, ok := payloadManager.GetQueue(queueName)
	if !ok {
		log.Printf("[POST /payload] Unauthorized queue: %s", queueName)
		http.Error(w, "payload queue not authorized", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("[POST /payload] Read body error: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var p Payload
	if err := json.Unmarshal(body, &p); err != nil {
		log.Printf("[POST /payload] Invalid JSON: %v", err)
		http.Error(w, "invalid payload JSON", http.StatusBadRequest)
		return
	}

	queue.Add(p)

		// Log truncated content
	log.Printf("[POST /payload] Added payload to queue '%s': Content='%s', Signature='%s'",
		queueName,
		truncateForLog(p.Content, 32),
		truncateForLog(p.Signature, 32),
	)

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"status":"payload queued"}`))
}

// ------------------------------------------------------------
// GET /payload/<queue>
func getPayload(w http.ResponseWriter, r *http.Request) {
	queueName, ok := extractQueueName(r.URL.Path)
	if !ok {
		log.Printf("[GET /payload] Invalid URL: %s", r.URL.Path)
		http.Error(w, "invalid URL", http.StatusBadRequest)
		return
	}

	queue, ok := payloadManager.GetQueue(queueName)
	if !ok {
		log.Printf("[GET /payload] Unauthorized queue: %s", queueName)
		http.Error(w, "payload queue not authorized", http.StatusForbidden)
		return
	}

	data := queue.GetAllAndClear()
	if len(data) > 0 {
		log.Printf("[GET /payload] Returned %d items from queue '%s'", len(data), queueName)
		for _, p := range data {
			truncMeta := compactTruncateJSON(p.Metadata, 128) // truncate metadata
			log.Printf("[GET /payload]: Metadata = %s, Signature='%s'",
				truncMeta,
				truncateForLog(p.Signature, 32),
			)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// ------------------------------------------------------------
// POST /response/<queue>
func postResponse(w http.ResponseWriter, r *http.Request) {
	queueName, ok := extractQueueName(r.URL.Path)
	if !ok {
		log.Printf("[POST /response] Invalid URL: %s", r.URL.Path)
		http.Error(w, "invalid URL", http.StatusBadRequest)
		return
	}

	queue, ok := responseManager.GetQueue(queueName)
	if !ok {
		log.Printf("[POST /response] Unauthorized queue: %s", queueName)
		http.Error(w, "response queue not authorized", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("[POST /response] Read body error: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var resp Response
	if err := json.Unmarshal(body, &resp); err != nil {
		log.Printf("[POST /response] Invalid JSON: %v", err)
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	queue.Add(resp)
		// Log truncated content
	log.Printf("[POST /response] Added response to queue '%s': Content='%s', Signature='%s'",
		queueName,
		truncateForLog(resp.Content, 32),
		truncateForLog(resp.Signature, 32),
	)

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"status":"response queued"}`))
}

// ------------------------------------------------------------
// GET /response/<queue>
func getResponse(w http.ResponseWriter, r *http.Request) {
	queueName, ok := extractQueueName(r.URL.Path)
	if !ok {
		log.Printf("[GET /response] Invalid URL: %s", r.URL.Path)
		http.Error(w, "invalid URL", http.StatusBadRequest)
		return
	}

	queue, ok := responseManager.GetQueue(queueName)
	if !ok {
		log.Printf("[GET /response] Unauthorized queue: %s", queueName)
		http.Error(w, "response queue not authorized", http.StatusForbidden)
		return
	}

	data := queue.GetAllAndClear()

	w.Header().Set("Content-Type", "application/json")

	// --- queue has data ---
	if len(data) > 0 {
		log.Printf("[GET /response] Returned %d items from queue '%s'", len(data), queueName)

		for _, resp := range data {
			truncMeta := compactTruncateJSON([]byte(resp.Metadata), 128)
			log.Printf("[GET /response]: Metadata = %s", truncMeta)
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "ok",
			"count":  len(data),
			"data":   data,
		})
		return
	}

	// --- queue empty ---
	log.Printf("[GET /response] Queue '%s' is empty", queueName)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "empty",
		"count":   0,
		"message": "no response available in queue",
		"data":    []interface{}{},
	})
}
// ------------------------------------------------------------
// mTLS server
// ------------------------------------------------------------

func createMTLSServer(certFile, keyFile, caFile string) (*http.Server, error) {
	serverCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/payload/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			postPayload(w, r)
			return
		}
		if r.Method == http.MethodGet {
			getPayload(w, r)
			return
		}
	})

	mux.HandleFunc("/response/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			postResponse(w, r)
			return
		}
		if r.Method == http.MethodGet {
			getResponse(w, r)
			return
		}
	})

	return &http.Server{
		Addr:      ":4433",
		Handler:   mux,
		TLSConfig: tlsConfig,
	}, nil
}


func loadQueuesFromEnv() map[string]bool {
	env := os.Getenv("OSOQUEUES")
	if env == "" {
		log.Fatal("OSOQUEUES environment variable not set")
	}

	auth := make(map[string]bool)

	for _, q := range strings.Fields(env) {
		auth[q] = true
	}

	log.Println("Authorized queues:", env)
	return auth
}

// ------------------------------------------------------------
// main
// ------------------------------------------------------------

func main() {
	server, err := createMTLSServer(
		"certs/server.crt",
		"certs/server.key",
		"certs/ca.crt",
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("mTLS payload/response queue server started on :4433")
	log.Fatal(server.ListenAndServeTLS("", ""))
}