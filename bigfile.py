#!/usr/bin/env python3

import sys
import os
import mimetypes
import logging
import json
import base64

# Import project modules
from src.sensora_client import config, bsv_utils2
from bsvlib import PrivateKey, TxOutput, Transaction
from bsvlib.script import Script

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- UPFILE Protocol Constants ---
UPFILE_JSON_PREFIX = "upfile "

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
        funding_script_hex = private_key.public_key().locking_script().hex()
        logger.info(f"Using wallet address: {funding_address} to fund upload.")
    except Exception as e:
        logger.error(f"Invalid WIF provided. Error: {e}"); sys.exit(1)
    
    try:
        with open(file_path, 'rb') as f:
            file_content_bytes = f.read()
        
        file_size = len(file_content_bytes)
        mime_type, _ = mimetypes.guess_type(file_path)
        if not mime_type: mime_type = "application/octet-stream"
        file_name = os.path.basename(file_path)

        logger.info(f"File: '{file_name}' ({mime_type})")
        logger.info(f"Size: {file_size / 1024:.2f} KB")

    except Exception as e:
        logger.error(f"Failed to read file: {e}"); sys.exit(1)

    # 2. Base64 encode the file data
    file_content_base64 = base64.b64encode(file_content_bytes).decode('ascii')

    # 3. Create the JSON Manifest
    manifest = {
        "version": 1,
        "filename": file_name,
        "mime": mime_type,
        "size": file_size,
        "description": "Uploaded with Sensora bigfile tool", # Optional
        "data": file_content_base64
    }
    
    # Combine prefix and JSON string, then encode to bytes
    final_payload_string = f"{UPFILE_JSON_PREFIX}{json.dumps(manifest)}"
    final_payload_bytes = final_payload_string.encode('utf-8')

    logger.info(f"Created JSON manifest. Total payload size: {len(final_payload_bytes)} bytes.")
    
    # Check against a practical OP_RETURN limit
    if len(final_payload_bytes) > 99000: # ~100KB limit
        logger.error("File is too large to upload with this single-transaction method after Base64 encoding.")
        logger.error("A chunked protocol would be required for this file.")
        sys.exit(1)

    # 4. Create and broadcast the transaction
    # We need a generic OP_RETURN creation function in the client's bsv_utils.
    # Let's borrow the one from the sensor agent.
    
    logger.info("--- Creating and Broadcasting Manifest Transaction ---")
    
    # We will use the generic OP_RETURN function we perfected for the sensor agent
    # This requires adding it to the client's bsv_utils module.
    # For now, let's assume it exists.
    
    # ACTION REQUIRED: Copy `create_and_broadcast_op_return_tx` from sensor_agent/src/bsv_utils.py
    # to sensora_client/src/bsv_utils.py.
    # We also need to add a lock for thread safety, even if we only use one thread here.
    import threading
    tx_lock = threading.Lock()

    # This call assumes you've copied the function over.
    txid = bsv_utils2.create_and_broadcast_op_return_tx(
        lock=tx_lock,
        priv_key_obj=private_key,
        pub_key_obj=private_key.public_key(),
        source_locking_script_hex=funding_script_hex,
        op_return_data=final_payload_bytes
    )
    
    if txid:
        logger.info(f"\n--- SUCCESS ---")
        logger.info(f"Transaction successfully broadcasted using UPFILE protocol!")
        logger.info(f"TXID: {txid}")
        logger.info(f"View on bitails.io: https://bitails.io/tx/{txid}")
    else:
        logger.error(f"\n--- FAILURE ---")
        logger.error("Transaction broadcast failed. Check the logs above.")

if __name__ == "__main__":
    main()