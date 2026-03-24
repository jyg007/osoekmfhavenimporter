import requests
import json
import logging
import time
import shutil
import os

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

INPUT_FILE = "INPUTBRIGDEOSMSGS"
BACKUP_FILE = "INPUTBRIGDEOSMSGS.bak"

OUTPUT_FILE = "OUTPUTBRIDGEMSGS"
SERVER_URL = "http://localhost:9080"
PROCESS_URL = f"{SERVER_URL}/BackendProcess?batch_size=20000"
MAX_LOG_LEN = 80  # maximum characters of content to log
INTERVAL = 5

def upload_doc(doc):
    content_len = len(doc['content'])
    snippet = doc['content'][:MAX_LOG_LEN] + ("..." if content_len > MAX_LOG_LEN else "")
    logging.info(f"Uploading document ID={doc['id']}, content length={content_len}, snippet={snippet}")

    resp = requests.post(f"{SERVER_URL}/BackEndKeysImportFilesUpload", json=doc)
    resp.raise_for_status()
    logging.info(resp.text.strip())

def process_messages():
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

    has_import = False
    has_keys_import = False

    # --- 3. Iterate and filter ---
    for doc in docs:
        metadata = doc.get("metadata")

        doc_type = None
        key_id = None     # initialize before parsing

        try:
            meta = json.loads(metadata)

            tx_type = meta.get("type")
            key_id = meta.get("keyid")

        except json.JSONDecodeError:
            pass

        content = doc.get("content")
        doc_id = doc.get("id")
        if tx_type  == "EKMFKEYSIMPORT":
            has_keys_import = True # Mark that we found a Keys Import
            upload_doc(doc)

        if tx_type == "EKMFIMPORT":
            logging.info(f"Condition met for ID: {doc_id}. Sending POST request...")
            
            try:
                payload = {
                    "id": doc_id,
                    "content": content,
                    "signature": doc.get("signature", ""),
                    "metadata": metadata
                }

                response = requests.post(
                    f"{SERVER_URL}/BackEndGetRSAKeyPair",  
                    json=payload,  
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code == 200:
                    logging.info(f"Successfully processed ID: {doc_id}")
                    
                    # --- 4. Append response to OUTPUTBRIDGEMSGS ---
                    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
                        # Writing the raw response text (the publicPEM or JSON) 
                        # and adding a newline so messages don't run together
                        f.write(response.text.strip() + "\n")
                
                else:
                    logging.warning(f"Backend returned error for ID {doc_id}: {response.status_code} - {response.text}")
            
            except requests.exceptions.RequestException as e:
               logging.error(f"Network error while calling backend for ID {doc_id}: {e}")
        # -----------------------------------------------------------
        # 2) NEW case: Upload Transport Key (EKMFTKEY)
        # -----------------------------------------------------------
        if tx_type == "EKMFTKEY":

            logging.info(f"Submitting transport key for ID: {key_id}")
            has_import = True # Mark that we found an Import
            
            try:
                payload = {
                    "id": doc_id,
                    "content": content,   # this is already the hex wrapped key
                    "signature": doc.get("signature", ""),
                    "metadata": metadata
                }
    
                response = requests.post(
                    "http://localhost:9080/BackendUploadTKey",
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code == 200:
                    logging.info(f"Transport key successfully uploaded for ID: {doc_id}")
                    logging.info(response.text)
                    
                    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
                        # Writing the raw response text (the publicPEM or JSON) 
                        # and adding a newline so messages don't run together
                        f.write(response.text.strip() + "\n")

                else:
                    logging.warning(
                        f"Upload failed for ID {doc_id}: {response.status_code} - {response.text}"
                    )

            except requests.exceptions.RequestException as e:
                logging.error(f"Network error while uploading transport key for ID {doc_id}")

    # --- 4. Final Trigger Call ---
    # Only calls if BOTH conditions were met at least once
    if has_keys_import:
        logging.info("Triggering BackendProcess...")
        try:
            final_resp = requests.post(PROCESS_URL)
            # Check response status and log reason if failed
            if final_resp.status_code >= 400:
                logging.error(
                    f"Failed to trigger final Batch process: "
                    f"{final_resp.status_code} {final_resp.reason} - {final_resp.text.strip()}"
                )
            else:
                # Append successful response to output file
                with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
                    f.write(final_resp.text.strip() + "\n")
                logging.info(f"Batch process triggered successfully: {final_resp.text.strip()}")
        except requests.RequestException as e:
            logging.error(f"Request exception when triggering final Batch process: {e}")
    else:
        logging.info("Criteria for final Batch process not met (requires both IMPORT types).")

             
if __name__ == "__main__":
    logging.info(f"OSO backend plugin started. Polling every {INTERVAL}s...")
    try:
        while True:  
            process_messages()
            time.sleep(INTERVAL)
    except KeyboardInterrupt:
        logging.info("Service stopped manually.")
