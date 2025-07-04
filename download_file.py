#!/usr/bin/env python3

import sys
import os
import logging
import json
import base64
import requests

# Assuming this script is in the root of sensora_client project
from src.sensora_client import config

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def parse_op_return_from_full_tx(tx_data: dict) -> bytes | None:
    """Finds and parses the first OP_RETURN data from a full transaction object."""
    outputs = tx_data.get('outputs', [])
    for output in outputs:
        script_hex = output.get('script')
        if script_hex and (script_hex.startswith("006a") or script_hex.startswith("6a")):
            # This is a basic parser. A more robust one would handle pushdata opcodes.
            # For now, let's assume bitcoind-style where data follows the opcode.
            try:
                # A simple way to get all data pushed after OP_RETURN/OP_FALSE OP_RETURN
                from bsvlib.script import Script
                return Script(bytes.fromhex(script_hex)).get_op_return()
            except Exception as e:
                logger.error(f"Could not parse OP_RETURN script {script_hex[:30]}...: {e}")
                return None
    return None

def get_full_transaction(txid: str) -> dict | None:
    """Fetches full transaction details from bitails.io."""
    try:
        url = f"{config.BITAILS_API_BASE_URL}/tx/{txid}"
        logger.info(f"Fetching transaction: {url}")
        response = requests.get(url, timeout=20)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.exception(f"Failed to get full transaction details for txid {txid}: {e}")
        return None

def main():
    if len(sys.argv) != 2:
        print("Usage: python download_file.py <manifest_txid>")
        sys.exit(1)

    manifest_txid = sys.argv[1]
    
    # 1. Fetch the manifest transaction
    manifest_tx_data = get_full_transaction(manifest_txid)
    if not manifest_tx_data:
        logger.error(f"Could not retrieve manifest transaction {manifest_txid}.")
        sys.exit(1)

    # 2. Find and parse the UPFILE manifest from the OP_RETURN
    op_return_payload = parse_op_return_from_full_tx(manifest_tx_data)
    if not op_return_payload:
        logger.error("No OP_RETURN found in the manifest transaction.")
        sys.exit(1)

    try:
        payload_str = op_return_payload.decode('utf-8')
        if not payload_str.startswith("upfile "):
            logger.error("OP_RETURN is not a valid UPFILE manifest.")
            sys.exit(1)
        
        manifest = json.loads(payload_str.split("upfile ", 1)[1])
        logger.info(f"Successfully parsed manifest for file: '{manifest.get('filename')}'")

    except (UnicodeDecodeError, json.JSONDecodeError, IndexError) as e:
        logger.exception(f"Failed to decode or parse JSON manifest: {e}")
        sys.exit(1)

    file_content_bytes = b''
    
    # 3. Check if data is inlined (small files) or chunked (large files)
    if "data" in manifest:
        # --- Handle Inlined Base64 Data ---
        logger.info("Found inlined Base64 data. Decoding...")
        try:
            file_content_bytes = base64.b64decode(manifest["data"])
        except Exception as e:
            logger.exception(f"Failed to decode Base64 data: {e}")
            sys.exit(1)

    elif "chunks" in manifest:
        # --- Handle Chunked Data ---
        chunk_txids = manifest.get("chunks", [])
        total_chunks = len(chunk_txids)
        logger.info(f"Found {total_chunks} data chunks. Reassembling file...")
        
        reassembled_chunks = []
        for i, chunk_txid in enumerate(chunk_txids):
            logger.info(f"--> Fetching chunk {i+1}/{total_chunks} (TXID: {chunk_txid[:10]}...)")
            chunk_tx_data = get_full_transaction(chunk_txid)
            if not chunk_tx_data:
                logger.error(f"Failed to retrieve chunk transaction {chunk_txid}. Aborting.")
                sys.exit(1)
            
            chunk_data = parse_op_return_from_full_tx(chunk_tx_data)
            if chunk_data is None:
                logger.error(f"Transaction {chunk_txid} did not contain parsable OP_RETURN data for the chunk.")
                sys.exit(1)
            
            reassembled_chunks.append(chunk_data)
        
        file_content_bytes = b''.join(reassembled_chunks)

    else:
        logger.error("Manifest is invalid: contains neither 'data' nor 'chunks' key.")
        sys.exit(1)

    # 4. Verify file size and save to disk
    expected_size = manifest.get("size")
    actual_size = len(file_content_bytes)

    if expected_size is not None and actual_size != expected_size:
        logger.warning(f"File size mismatch! Manifest expected {expected_size} bytes, but reassembled file is {actual_size} bytes.")
    else:
        logger.info(f"File size matches manifest: {actual_size} bytes.")

    output_filename = manifest.get("filename", "downloaded_file")
    # Sanitize filename to prevent directory traversal
    output_filename = os.path.basename(output_filename) 

    try:
        with open(output_filename, 'wb') as f:
            f.write(file_content_bytes)
        logger.info(f"\n--- SUCCESS ---")
        logger.info(f"File successfully downloaded and saved as '{output_filename}'")
    except Exception as e:
        logger.exception(f"Failed to save the file to disk: {e}")

if __name__ == "__main__":
    main()