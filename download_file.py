#!/usr/bin/env python3

import sys
import os
import logging
import json
import base64
import requests
import struct

from src.sensora_client import config
from bsvlib import Transaction

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(name)s] %(module)s.%(funcName)s - %(message)s')
logger = logging.getLogger(__name__)

def get_raw_tx_hex_from_bitails(txid: str) -> str | None:
    try:
        url = f"{config.BITAILS_API_BASE_URL}/download/tx/{txid}"
        logger.info(f"Fetching raw binary transaction from: {url}")
        response = requests.get(url, timeout=45)
        response.raise_for_status()
        binary_data = response.content
        if not binary_data:
            logger.error(f"Received empty binary data for txid {txid}")
            return None
        return binary_data.hex()
    except Exception as e:
        logger.exception(f"Failed to get and convert raw transaction for txid {txid}: {e}")
        return None

# --- START FINAL CORRECTION: Use the manual parser we know works ---
def parse_op_return_from_hex(script_hex: str) -> bytes | None:
    """
    Manually parses the data payload from a full OP_RETURN script hex.
    """
    try:
        if script_hex.startswith("006a"):
            script_bytes = bytes.fromhex(script_hex[4:])
        elif script_hex.startswith("6a"):
            script_bytes = bytes.fromhex(script_hex[2:])
        else:
            return None

        if not script_bytes: return b''

        opcode = script_bytes[0]
        data_start = 0
        length_to_read = 0

        if 0x01 <= opcode <= 0x4b:
            length_to_read = opcode; data_start = 1
        elif opcode == 0x4c:
            if len(script_bytes) < 2: return None
            length_to_read = script_bytes[1]; data_start = 2
        elif opcode == 0x4d:
            if len(script_bytes) < 3: return None
            length_to_read = int.from_bytes(script_bytes[1:3], 'little'); data_start = 3
        elif opcode == 0x4e:
            if len(script_bytes) < 5: return None
            length_to_read = int.from_bytes(script_bytes[1:5], 'little'); data_start = 5
        else:
            return None
        
        if len(script_bytes) < data_start + length_to_read:
            logger.warning(f"Script indicates data length {length_to_read} but only {len(script_bytes)-data_start} bytes available.")
            return None
            
        return script_bytes[data_start : data_start + length_to_read]
    except Exception as e:
        logger.exception(f"Error manually parsing OP_RETURN hex '{script_hex[:30]}...': {e}")
        return None

def find_and_parse_op_return_from_txid(txid: str) -> bytes | None:
    """
    Given a TXID, fetches the raw transaction and parses its OP_RETURN using the manual parser.
    """
    raw_tx_hex = get_raw_tx_hex_from_bitails(txid)
    if not raw_tx_hex: return None
        
    try:
        tx = Transaction.from_hex(raw_tx_hex)
        for output in tx.tx_outputs:
            script_hex = output.locking_script.hex()
            if script_hex.startswith('006a') or script_hex.startswith('6a'):
                # Call our own reliable parser
                return parse_op_return_from_hex(script_hex)
        
        logger.warning(f"No OP_RETURN output found in transaction {txid}")
        return None
    except Exception as e:
        logger.exception(f"Failed to parse raw transaction hex for {txid}: {e}")
        return None
# --- END FINAL CORRECTION ---

def main():
    if len(sys.argv) != 2:
        print("Usage: python download_file.py <manifest_txid>")
        sys.exit(1)

    manifest_txid = sys.argv[1]
    
    logger.info("--- Step 1: Fetching Manifest Transaction ---")
    op_return_payload = find_and_parse_op_return_from_txid(manifest_txid)
    
    if op_return_payload is None:
        logger.critical(f"Could not retrieve or parse manifest from transaction {manifest_txid}. Aborting.")
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
    
    if "data" in manifest:
        logger.info("Manifest contains inlined Base64 data. Decoding...")
        try:
            file_content_bytes = base64.b64decode(manifest["data"])
        except Exception as e:
            logger.exception(f"Failed to decode Base64 data: {e}"); sys.exit(1)
            
    elif "chunks" in manifest:
        chunk_txids = manifest.get("chunks", [])
        total_chunks = len(chunk_txids)
        logger.info(f"--- Step 2: Reassembling from {total_chunks} Data Chunks ---")
        
        reassembled_chunks = []
        for i, chunk_txid in enumerate(chunk_txids):
            logger.info(f"--> Fetching chunk {i+1}/{total_chunks} (TXID: {chunk_txid[:10]}...)")
            chunk_data = find_and_parse_op_return_from_txid(chunk_txid)
            if chunk_data is None:
                logger.error(f"Failed to retrieve data from chunk TX {chunk_txid}. Aborting."); sys.exit(1)
            reassembled_chunks.append(chunk_data)
        
        file_content_bytes = b''.join(reassembled_chunks)
    else:
        logger.error("Manifest is invalid: contains neither 'data' nor 'chunks' key."); sys.exit(1)

    expected_size = manifest.get("size")
    actual_size = len(file_content_bytes)

    if expected_size is not None and actual_size != expected_size:
        logger.warning(f"File size mismatch! Manifest expected {expected_size} bytes, but reassembled file is {actual_size} bytes.")
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