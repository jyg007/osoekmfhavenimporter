import requests
import json
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

SERVER_URL = "http://localhost:8080"
MAX_LOG_LEN = 80  # maximum characters of content to log
OUTPUT_FILE = "INPUTBRIGDEOSMSGS"


def get_import_txs():
    try:
        resp = requests.get(f"{SERVER_URL}/FrontEndGetEMKFOSOMsgs?keys_per_doc=10000")
        resp.raise_for_status()
        docs = resp.json()
        if docs is None:
            return []
        return docs
    except Exception as e:
        logging.error(f"Failed to fetch data: {e}")
        return []

def main():
    docs = get_import_txs()
    
    if not docs:
        logging.info("No documents to retrieve from server. Exiting.")
        return

    logging.info(f"Retrieved {len(docs)} documents from server.")

    # Writing to the file
    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            # We save the entire list as a formatted JSON array
            json.dump(docs, f, indent=4)
        
        logging.info(f"Successfully wrote {len(docs)} documents to {OUTPUT_FILE}")
    except IOError as e:
        logging.error(f"Could not write to file: {e}")
        return

    # Optional: Log snippets of what was saved
    for doc in docs:
        content = doc.get('content', '')
        content_len = len(content)
        snippet = content[:MAX_LOG_LEN] + ("..." if content_len > MAX_LOG_LEN else "")
        logging.info(f"Saved document ID={doc.get('id')}, len={content_len}, snippet={snippet}")

if __name__ == "__main__":
    main()
