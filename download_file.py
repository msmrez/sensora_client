#!/usr/bin/env python3

import sys
import os
import logging
import json
import base64
import requests
import struct

# Assuming this script is in the root of sensora_client project
from src.sensora_client import config

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(name)s] %(module)s.%(funcName)s - %(message)s')
logger = logging.getLogger(__name__)

def parse_op_return_from_script_hex(script_hex: str) -> bytes | None:
    """
    Parses data from a full OP_RETURN script hex by manually handling pushdata opcodes.
    Includes a check to ensure the script is not truncated.
    """
    try:
        if script_hex.startswith("006a"): # OP_FALSE OP_RETURN
            script_bytes = bytes.fromhex(script_hex[4:])
        elif script_hex.startswith("6a"): # OP_RETURN
            script_bytes = bytes.fromhex(script_hex[2:])
        else:
            return None # Not a recognized OP_RETURN script

        if not script_bytes:
            return b'' # Empty OP_RETURN

        opcode = script_bytes[0]
        data_start = 0
        length_to_read = 0

        if 0x01 <= opcode <= 0x4b: # Direct push of 1-75 bytes
            length_to_read = opcode
            data_start = 1
        elif opcode == 0x4c: # OP_PUSHDATA1
            if len(script_bytes) < 2: return None
            length_to_read = script_bytes[1]
            data_start = 2
        elif opcode == 0x4d: # OP_PUSHDATA2
            if len(script_bytes) < 3: return None
            length_to_read = int.from_bytes(script_bytes[1:3], 'little')
            data_start = 3
        elif opcode == 0x4e: # OP_PUSHDATA4
            if len(script_bytes) < 5: return None
            length_to_read = int.from_bytes(script_bytes[1:5], 'little')
            data_start = 5
        else:
            return None # Not a standard push opcode we expect first
        
        # This is the crucial check for truncated scripts
        if len(script_bytes) < data_start + length_to_read:
            logger.warning(f"Script indicates data length {length_to_read} but only {len(script_bytes)-data_start} bytes are available. Script is truncated.")
            return None
            
        return script_bytes[data_start : data_start + length_to_read]
    except Exception as e:
        logger.exception(f"Error manually parsing OP_RETURN hex '{script_hex[:30]}...': {e}")
        return None

def find_and_parse_op_return_from_tx_data(tx_data: dict) -> bytes | None:
    """Finds and parses the OP_RETURN from a full transaction JSON object from bitails.io."""
    txid = tx_data.get('txid', '[unknown]')
    outputs = tx_data.get('outputs', [])
    for output in outputs:
        # We look for the 'nulldata' type which bitails.io correctly identifies
        if output.get('type') == 'nulldata':
            script_hex = output.get('script')
            if script_hex:
                logger.info(f"Found nulldata output in TX {txid}. Attempting to parse...")
                # We attempt to parse it regardless of the 'partialScript' flag.
                # Our parser will determine if it's actually truncated.
                return parse_op_return_from_script_hex(script_hex)
    
    logger.warning(f"No parsable 'nulldata' output found in transaction {txid}")
    return None

def get_full_transaction(txid: str) -> dict | None:
    """Fetches full transaction details from bitails.io."""
    try:
        url = f"{config.BITAILS_API_BASE_URL}/tx/{txid}"
        logger.info(f"Fetching transaction: {url}")
        response = requests.get(url, timeout=30) # Increased timeout for potentially large JSON
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
        logger.error(f"Could not retrieve manifest transaction {manifest_txid}. Exiting.")
        sys.exit(1)

    op_return_payload = find_and_parse_op_return_from_tx_data(manifest_tx_data)
    if op_return_payload is None:
        logger.error(f"Could not parse OP_RETURN from manifest transaction {manifest_txid}. Exiting.")
        sys.exit(1)

    try:
        payload_str = op_return_payload.decode('utf-8')
        if not payload_str.startswith("upfile "):
            logger.error("OP_RETURN is not a valid UPFILE manifest."); sys.exit(1)
        manifest = json.loads(payload_str.split("upfile ", 1)[1])
        logger.info(f"Successfully parsed manifest for file: '{manifest.get('filename')}'")
    except Exception as e:
        logger.exception(f"Failed to decode or parse JSON manifest: {e}"); sys.exit(1)

    file_content_bytes = b''
    
    # Check if data is inlined (small files) or chunked (large files)
    if "data" in manifest:
        logger.info("Found inlined Base64 data. Decoding...")
        try:
            file_content_bytes = base64.b64decode(manifest["data"])
        except Exception as e:
            logger.exception(f"Failed to decode Base64 data: {e}")
            sys.exit(1)
            
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
                logger.error(f"Transaction {chunk_txid} did not contain a valid/complete OP_RETURN data chunk. Aborting."); sys.exit(1)
            
            reassembled_chunks.append(chunk_data)
        
        file_content_bytes = b''.join(reassembled_chunks)
    else:
        logger.error("Manifest is invalid: contains neither 'data' nor 'chunks' key."); sys.exit(1)

    # Verify file size and save to disk
    expected_size = manifest.get("size")
    actual_size = len(file_content_bytes)

    if expected_size is not None and actual_size != expected_size:
        logger.warning(f"File size mismatch! Manifest expected {expected_size} bytes, but reassembled file has {actual_size} bytes.")
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