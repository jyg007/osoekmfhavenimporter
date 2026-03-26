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
MAX_LOG_LEN = 80  # maximum characters of content to log

def to_oso():
   
    try:
        response = requests.get(f"{SERVER_URL}/BackendGetEKMFMsgs")
        response.raise_for_status()

        txs = response.json()  # expected: a list of ImportTx objects

        if not txs:
            return

        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            for tx in txs:
                # Dump the whole tx dict as a single JSON line
                f.write(json.dumps(tx, separators=(",", ":")) + "\n")

        logging.info(f"Saved {len(txs)} transactions")

    except requests.RequestException as e:
        logging.error(f"Failed to fetch transactions: {e}")
    except json.JSONDecodeError as e:
        logging.error(f"Failed to decode JSON: {e}")


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
                        f"{SERVER_URL}/BackendPostEKMFMsg",
                        json=doc,
                        headers={"Content-Type": "application/json"},
                    )
                    if response.status_code == 204:
                        logging.info(f"Successfully processed EKMF msg: {doc_id}")
                    else:
                        logging.warning(f"Backend returned error for EKMF ID {doc_id}: {response.status_code} - {response.text}")
                except requests.exceptions.RequestException as e:
                    logging.error(f"Network error for ID {doc_id}: {e}")

    ########################################################################################
    # --- Final Trigger Call ---
    try:
       final_resp = requests.post(f"{SERVER_URL}/BackendEKMFImport?batch_size=20000")
       # Check response status and log reason if failed
       if final_resp.status_code >= 400:
           logging.error(
               f"Failed to trigger final Batch process: "
               f"{final_resp.status_code} {final_resp.reason} - {final_resp.text.strip()}"
            )
    except requests.RequestException as e:
            logging.error(f"Request exception when triggering final Batch process: {e}")
####################################################################
#        else:
#  Non-EKMF processing
#####################################################        

             
if __name__ == "__main__":
    logging.info(f"OSO backend plugin started")
    to_ekmf()
    to_oso()
