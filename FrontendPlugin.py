import requests
import json
import logging
import time  

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

SERVER_URL = "http://localhost:8080"
MAX_LOG_LEN = 80  # maximum characters of content to log
OUTPUT_FILE = "INPUTQUEUEMSGS"
INTERVAL = 5  # Seconds to wait between queries

def get_import_txs():
    try:                                 
        resp = requests.get(f"{SERVER_URL}/FrontendGetMsgs?keys_per_doc=10000")
        resp.raise_for_status()
        docs = resp.json()
        if docs is None:
            return []
        return docs
    except Exception as e:
        logging.error(f"Failed to fetch data: {e}")
        return []

def main():
    logging.info("Starting frontend plugin in infinite loop...")
    while True:
        docs = get_import_txs()
        
        if not docs:
            #logging.info("No documents to retrieve from server. Exiting.")
            time.sleep(INTERVAL)
            continue
    
        logging.info(f"Retrieved {len(docs)} documents from server.")
    
        # Writing to the file
        try:
            with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
                for doc in docs:
                    # Write each dict as a single line
                    f.write(json.dumps(doc) + "\n")
            
            logging.info(f"Appended {len(docs)} documents to {OUTPUT_FILE}")
        except IOError as e:
            logging.error(f"Could not write to file: {e}")
            return
    
        # Optional: Log snippets of what was saved
        for doc in docs:
            content = doc.get('content', '')
            content_len = len(content)
            snippet = content[:MAX_LOG_LEN] + ("..." if content_len > MAX_LOG_LEN else "")
            logging.info(f"Saved document ID={doc.get('id')}, len={content_len}, snippet={snippet}")

        # 3. Wait for the specified interval

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Script stopped by user (Ctrl+C).")
