import requests
import json
import logging
import time  
import os
import shutil 

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

SERVER_URL = "http://localhost:8080"
MAX_LOG_LEN = 80  # maximum characters of content to log
OUTPUT_FILE = "INPUTQUEUEMSGS"
INTERVAL = 5  # Seconds to wait between queries

INPUT_FILE="OUTPUTBRIDGEMSGS"
BACKUP_FILE="OUTPUTBRIDGEMSGS.bak"

def to_oso():
    try:                                  
        resp = requests.get(f"{SERVER_URL}/FrontendDownloadEKMFMsgs?keys_per_doc=10000")
        resp.raise_for_status()
        docs = resp.json()
        if docs is None:
            return
    except Exception as e:
        logging.error(f"Failed to fetch data: {e}")
        return 
 
    logging.info(f"Retrieved {len(docs)} documents from server.")
 
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

def to_ekmf():
    # --- 1. Load the documents ---
    try:
        if os.path.exists(INPUT_FILE) and os.path.getsize(INPUT_FILE) > 0:
             with open(INPUT_FILE, "r", encoding="utf-8") as f:
                 # Parses lines. If the file is 0 bytes, docs becomes []
                 docs = [json.loads(line) for line in f if line.strip()]

             if docs:
                 logging.info(f"Loaded {len(docs)} documents from {INPUT_FILE}")
           
                 # 1. Backup
                 shutil.copy2(INPUT_FILE, BACKUP_FILE)

                 # 2. CLEAR the file properly (0 bytes)
                 # Opening in 'w' mode and immediately closing empties the file.
                 with open(INPUT_FILE, "w", encoding="utf-8") as f:
                     pass 
             else:
                 return
        else:
             return
    except Exception as e:
        logging.error(f"Error: {e}")
        return
 
    # --- 2. Clear the output file at startup ---
    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("") # Truncate file
        logging.info(f"Initialized {OUTPUT_FILE} (cleared).")
    except Exception as e:
        logging.error(f"Could not initialize output file: {e}")
        return

    ########################################################################################
    # --- 3. Iterate and filter ---
    for doc in docs:
        metadata = doc.get("metadata")
        doc_id = doc.get("id")
        source = None

        try:
            meta = json.loads(metadata)
            source = meta.get("source")
        except json.JSONDecodeError:
            logging.warning(f"Failed to parse metadata for doc ID: {doc_id}")
            continue

        # --- EKMF source handling ---
        if source == "EKMF":
                try:
                    response = requests.post(
                        f"{SERVER_URL}/FrontendUploadEKMFMsgs",
                        json=doc,
                        headers={"Content-Type": "application/json"},
                    )
                    if response.status_code == 200:
                        logging.info(f"Successfully processed EKMF msg: {doc_id}")
                    else:
                        logging.warning(f"Frontend returned error for EKMF ID {doc_id}: {response.status_code} - {response.text}")
                except requests.exceptions.RequestException as e:
                    logging.error(f"Network error for ID {doc_id}: {e}")

def main():
    logging.info("Starting frontend plugin in infinite loop...")
    while True:
        to_oso()
        time.sleep(INTERVAL)
        to_ekmf()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Script stopped by user (Ctrl+C).")
