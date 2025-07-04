#!/usr/bin/env python3

import sys
import os
import logging
import json
import base64
import requests
import struct

from src.sensora_client import config

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def parse_op_return_from_script_hex(script_hex: str) -> bytes | None:
    # This manual parser is correct.
    try:
        if script_hex.startswith("006a"): script_bytes = bytes.fromhex(script_hex[4:])
        elif script_hex.startswith("6a"): script_bytes = bytes.fromhex(script_hex[2:])
        else: return None
        if not script_bytes: return b''
        opcode = script_bytes[0]
        if 0x01 <= opcode <= 0x4b: length_to_read = opcode; data_start = 1
        elif opcode == 0x4c: length_to_read = script_bytes[1]; data_start = 2
        elif opcode == 0x4d: length_to_read = int.from_bytes(script_bytes[1:3], 'little'); data_start = 3
        elif opcode == 0x4e: length_to_read = int.from_bytes(script_bytes[1:5], 'little'); data_start = 5
        else: return None
        if len(script_bytes) < data_start + length_to_read:
            logger.warning(f"Script indicates length {length_to_read} but only {len(script_bytes)-data_start} bytes are available. Script is likely truncated.")
            return None
        return script_bytes[data_start : data_start + length_to_read]
    except Exception as e:
        logger.exception(f"Error manually parsing OP_RETURN hex: {e}"); return None

def find_and_parse_op_return_from_tx_data(tx_data: dict) -> bytes | None:
    """Finds and parses the OP_RETURN from a full transaction JSON object from bitails.io."""
    outputs = tx_data.get('outputs', [])
    for output in outputs:
        if output.get('type') == 'nulldata':
            script_hex = output.get('script')
            if script_hex:
                logger.info("Found nulldata output. Attempting to parse...")
                # We will attempt to parse it regardless of the 'partialScript' flag.
                # If the data is truly truncated, our parser's length check should catch it.
                return parse_op_return_from_script_hex(script_hex)
    logger.warning(f"No parsable 'nulldata' output found in transaction {tx_data.get('txid')}")
    return None

def get_full_transaction(txid: str) -> dict | None:
    try:
        url = f"{config.BITAILS_API_BASE_URL}/tx/{txid}"
        logger.info(f"Fetching transaction: {url}")
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.exception(f"Failed to get transaction details for txid {txid}: {e}")
        return None

def main():
    if len(sys.argv) != 2:
        print("Usage: python download_file.py <manifest_txid>")
        sys.exit(1)

    manifest_txid = sys.argv[1]
    
    logger.info("--- Step 1: Fetching Manifest Transaction ---")
    manifest_tx_data = get_full_transaction(manifest_txid)
    if not manifest_tx_data:
        logger.error(f"Could not retrieve manifest transaction {manifest_txid}."); sys.exit(1)

    op_return_payload = find_and_parse_op_return_from_tx_data(manifest_tx_data)
    if op_return_payload is None:
        logger.error(f"Could not parse OP_RETURN from manifest transaction {manifest_txid}."); sys.exit(1)

    # ... (rest of the main function remains exactly the same)
    try:
        payload_str = op_return_payload.decode('utf-8')
        if not payload_str.startswith("upfile "):
            logger.error("OP_RETURN is not a valid UPFILE manifest."); sys.exit(1)
        manifest = json.loads(payload_str.split("upfile ", 1)[1])
        logger.info(f"Successfully parsed manifest for file: '{manifest.get('filename')}'")
    except Exception as e:
        logger.exception(f"Failed to decode or parse JSON manifest: {e}"); sys.exit(1)

    file_content_bytes = b''
    
    if "data" in manifest:
        # ...
    elif "chunks" in manifest:
        chunk_txids = manifest.get("chunks", [])
        total_chunks = len(chunk_txids)
        logger.info(f"--- Step 2: Reassembling from {total_chunks} Data Chunks ---")
        reassembled_chunks = []
        for i, chunk_txid in enumerate(chunk_txids):
            logger.info(f"--> Fetching chunk {i+1}/{total_chunks} (TXID: {chunk_txid[:10]}...)")
            chunk_tx_data = get_full_transaction(chunk_txid)
            if not chunk_tx_data:
                logger.error(f"Failed to retrieve chunk transaction {chunk_txid}. Aborting."); sys.exit(1)
            
            chunk_data = find_and_parse_op_return_from_tx_data(chunk_tx_data)
            if chunk_data is None:
                logger.error(f"Transaction {chunk_txid} did not contain parsable OP_RETURN data. Aborting."); sys.exit(1)
            reassembled_chunks.append(chunk_data)
        
        file_content_bytes = b''.join(reassembled_chunks)
    else:
        logger.error("Manifest is invalid: contains neither 'data' nor 'chunks' key."); sys.exit(1)

    # ... (rest of main function for verifying and saving is the same)
    expected_size = manifest.get("size")
    actual_size = len(file_content_bytes)

    if expected_size is not None and actual_size != expected_size:
        logger.warning(f"File size mismatch! Manifest: {expected_size}, Reassembled: {actual_size}.")
    else:
        logger.info(f"File size matches manifest: {actual_size} bytes.")

    output_filename = os.path.basename(manifest.get("filename", "downloaded_file")) 

    try:
        with open(output_filename, 'wb') as f:
            f.write(file_content_bytes)
        logger.info(f"\n--- SUCCESS ---")
        logger.info(f"File successfully downloaded and saved as '{output_filename}'")
    except Exception as e:
        logger.exception(f"Failed to save the file to disk: {e}")

if __name__ == "__main__":
    main()