#!/usr/bin/env python3

import sys
import os
import mimetypes
import logging
import json
import base64
import threading

# Import project modules
from src.sensora_client import config
# --- START CORRECTION: Import from the correct utility file ---
from src.sensora_client import bsv_utils2
# --- END CORRECTION ---

from bsvlib import PrivateKey

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- UPFILE Protocol Constants ---
UPFILE_JSON_PREFIX = "upfile "
SINGLE_TX_SIZE_LIMIT = 900 * 1024
CHUNK_SIZE_BYTES = 1000 * 1024

def upload_file_as_chunks(file_content_bytes, file_name, mime_type, private_key):
    """Handles the multi-transaction upload for large files."""
    
    file_chunks = [file_content_bytes[i:i + CHUNK_SIZE_BYTES] for i in range(0, len(file_content_bytes), CHUNK_SIZE_BYTES)]
    logger.info(f"File is large. Splitting into {len(file_chunks)} chunks of max {CHUNK_SIZE_BYTES // 1024} KB.")
    
    chunk_txids = []
    tx_lock = threading.Lock()

    for i, chunk in enumerate(file_chunks):
        logger.info(f"--- Uploading Chunk {i+1}/{len(file_chunks)} ---")
        
        # --- START CORRECTION: Call the function from the correct module ---
        chunk_txid = bsv_utils2.create_and_broadcast_op_return_tx(
            lock=tx_lock,
            priv_key=private_key,
            op_return_data=chunk
        )
        # --- END CORRECTION ---

        if not chunk_txid:
            logger.error(f"Failed to upload chunk {i+1}. Aborting upload.")
            return None
        
        chunk_txids.append(chunk_txid)
        logger.info(f"Chunk {i+1} uploaded successfully. TXID: {chunk_txid}")

    logger.info("All chunks uploaded. Creating final manifest...")
    manifest = {
        "version": 1, "filename": file_name, "mime": mime_type,
        "size": len(file_content_bytes), "description": "Chunked upload via Sensora",
        "chunksize": CHUNK_SIZE_BYTES, "chunks": chunk_txids
    }
    manifest_string = f"{UPFILE_JSON_PREFIX}{json.dumps(manifest)}"
    manifest_bytes = manifest_string.encode('utf-8')

    logger.info("--- Uploading Manifest Transaction ---")
    manifest_txid = bsv_utils2.create_and_broadcast_op_return_tx(
        lock=tx_lock,
        priv_key=private_key,
        op_return_data=manifest_bytes
    )
    return manifest_txid

def upload_file_as_single_tx(file_content_bytes, file_name, mime_type, private_key):
    """Handles the single-transaction upload for small files."""
    logger.info("File is small. Using single transaction method with inline Base64 data.")
    
    file_content_base64 = base64.b64encode(file_content_bytes).decode('ascii')
    
    manifest = {
        "version": 1, "filename": file_name, "mime": mime_type,
        "size": len(file_content_bytes), "description": "Single-TX upload via Sensora",
        "data": file_content_base64
    }
    manifest_string = f"{UPFILE_JSON_PREFIX}{json.dumps(manifest)}"
    manifest_bytes = manifest_string.encode('utf-8')

    if len(manifest_bytes) >= 99500:
        logger.error("Encoded manifest is too large for a single transaction.")
        return None
    
    logger.info("--- Creating and Broadcasting Manifest Transaction ---")
    tx_lock = threading.Lock()
    
    # --- START CORRECTION: Call the function from the correct module ---
    return bsv_utils2.create_and_broadcast_op_return_tx(
        lock=tx_lock,
        priv_key=private_key,
        op_return_data=manifest_bytes
    )
    # --- END CORRECTION ---

def main():
    if len(sys.argv) != 3:
        print("Usage: python bigfile.py <path_to_file> <your_paying_wif>")
        sys.exit(1)

    file_path = sys.argv[1]
    wif_string = sys.argv[2]

    if not os.path.exists(file_path): logger.error(f"File not found: {file_path}"); sys.exit(1)
    try:
        private_key = PrivateKey(wif_string)
        logger.info(f"Using wallet address: {private_key.public_key().address()} to fund upload.")
    except Exception as e:
        logger.error(f"Invalid WIF provided. Error: {e}"); sys.exit(1)
    
    with open(file_path, 'rb') as f:
        file_content_bytes = f.read()
    
    file_size = len(file_content_bytes)
    mime_type, _ = mimetypes.guess_type(file_path)
    if not mime_type: mime_type = "application/octet-stream"
    file_name = os.path.basename(file_path)
    
    logger.info(f"File: '{file_name}' ({mime_type}), Size: {file_size / 1024:.2f} KB")

    if file_size > SINGLE_TX_SIZE_LIMIT:
        final_txid = upload_file_as_chunks(file_content_bytes, file_name, mime_type, private_key)
    else:
        final_txid = upload_file_as_single_tx(file_content_bytes, file_name, mime_type, private_key)

    if final_txid:
        logger.info(f"\n--- UPLOAD COMPLETE ---")
        logger.info(f"Final Manifest TXID: {final_txid}")
        logger.info(f"View on bitails.io: https://bitails.io/tx/{final_txid}")
    else:
        logger.error(f"\n--- UPLOAD FAILED ---")

if __name__ == "__main__":
    main()