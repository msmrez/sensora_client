#!/usr/bin/env python3

import sys
import os
import mimetypes
import logging
import json
import threading

# Import project modules
from src.sensora_client import config, bsv_utils2
from bsvlib import PrivateKey

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- UPFILE Protocol Constants ---
# Files larger than this will be rejected by this script, as they won't fit in one transaction.
FILE_SIZE_LIMIT = 98 * 1024 # 98KB is a safe limit for a single OP_RETURN

def main():
    if len(sys.argv) != 3:
        print("Usage: python bigfile.py <path_to_file> <your_paying_wif>")
        sys.exit(1)

    file_path = sys.argv[1]
    wif_string = sys.argv[2]

    # 1. Validate inputs and read file
    if not os.path.exists(file_path):
        logger.error(f"File not found at: {file_path}"); sys.exit(1)

    try:
        private_key = PrivateKey(wif_string)
        funding_address = private_key.public_key().address()
        logger.info(f"Using wallet address: {funding_address} to fund upload.")
    except Exception as e:
        logger.error(f"Invalid WIF provided. Error: {e}"); sys.exit(1)
    
    try:
        with open(file_path, 'rb') as f:
            file_content_bytes = f.read()
        
        file_size = len(file_content_bytes)
        if file_size > FILE_SIZE_LIMIT:
            logger.error(f"File size ({file_size} bytes) exceeds the single transaction limit of {FILE_SIZE_LIMIT} bytes.")
            logger.error("Please use a smaller file or implement a chunking uploader.")
            sys.exit(1)

        mime_type, _ = mimetypes.guess_type(file_path)
        if not mime_type: mime_type = "application/octet-stream"
        file_name = os.path.basename(file_path)
        
        logger.info(f"File: '{file_name}' ({mime_type}), Size: {file_size / 1024:.2f} KB")
    except Exception as e:
        logger.error(f"Failed to read file: {e}"); sys.exit(1)

    # 2. Create the JSON Manifest (without the data field)
    manifest = {
        "version": 2, # V2 for hybrid protocol
        "filename": file_name,
        "mime": mime_type,
        "size": file_size,
        "description": "Hybrid upload via Sensora"
    }
    manifest_bytes = json.dumps(manifest).encode('utf-8')
    logger.info("Created JSON manifest for hybrid upload.")

    # 3. Create and broadcast the transaction using the new hybrid utility
    logger.info("--- Creating and Broadcasting Hybrid Transaction ---")
    tx_lock = threading.Lock()
    
    final_txid = bsv_utils2.create_hybrid_op_return_tx(
        lock=tx_lock,
        private_key=private_key,
        manifest_bytes=manifest_bytes,
        file_binary_data=file_content_bytes
    )

    # 4. Report result
    if final_txid:
        logger.info(f"\n--- UPLOAD COMPLETE ---")
        logger.info(f"Final Manifest TXID: {final_txid}")
        logger.info(f"View on bitails.io: https://bitails.io/tx/{final_txid}")
    else:
        logger.error(f"\n--- UPLOAD FAILED ---")
        logger.error("File upload failed. Check logs for details (e.g., insufficient funds).")

if __name__ == "__main__":
    main()