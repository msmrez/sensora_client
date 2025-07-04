#!/usr/bin/env python3

import sys
import os
import logging
import json
import base64
import requests

# Import project modules
from src.sensora_client import config
from bsvlib import Transaction

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(name)s] %(module)s.%(funcName)s - %(message)s')
logger = logging.getLogger(__name__)

def find_and_parse_op_return_from_txid(txid: str) -> bytes | None:
    """
    Given a TXID, fetches the transaction details and parses its OP_RETURN.
    It prioritizes finding the full raw transaction hex for parsing.
    """
    try:
        url = f"{config.BITAILS_API_BASE_URL}/tx/{txid}"
        logger.info(f"Fetching transaction details: {url}")
        response = requests.get(url, timeout=20)
        response.raise_for_status()
        tx_data = response.json()
    except Exception as e:
        logger.exception(f"Failed to get transaction details for txid {txid}: {e}")
        return None

    # --- Primary Method: Look for full raw transaction hex in the response ---
    # Common keys for this are 'hex' or 'rawtx'.
    raw_tx_hex = tx_data.get("hex") or tx_data.get("rawtx")

    if raw_tx_hex:
        logger.info("Found full raw transaction hex in API response. Parsing...")
        try:
            # Use bsvlib to parse the raw transaction hex
            tx = Transaction.from_hex(raw_tx_hex)
            for output in tx.tx_outputs:
                if output.script.is_op_return():
                    # This is the most reliable way to get the OP_RETURN data
                    op_return_data = output.script.get_op_return()
                    if op_return_data: # It might be a list of pushes
                        # For UPFILE, we expect a single data push
                        return op_return_data[0] if isinstance(op_return_data, list) else op_return_data
            
            logger.warning(f"Parsed raw hex for {txid}, but no OP_RETURN output was found.")
            return None
        except Exception as e:
            logger.exception(f"Failed to parse raw transaction hex for {txid}: {e}")
            return None
    
    # --- Fallback Method: Check the 'outputs' array ---
    # This will only work if scripts are not partial.
    logger.warning(f"Full raw 'hex' not found in response for {txid}. Attempting to parse from 'outputs' array.")
    outputs = tx_data.get('outputs', [])
    for output in outputs:
        # Check if this is a 'nulldata' (OP_RETURN) output
        if output.get('type') == 'nulldata':
            # Check if the script is truncated by the API
            if output.get('partialScript') == True:
                logger.error(f"OP_RETURN script is partial and no full transaction hex was provided by the API for {txid}. Cannot reassemble file.")
                return None
            
            script_hex = output.get('script')
            if script_hex:
                # If not partial, we can try to parse it, but this requires a manual parser
                # as we don't have the bsvlib Script object. The raw hex method is superior.
                # For this script's purpose, we will consider this a failure path if we reach here with large files.
                logger.error(f"Found a non-partial OP_RETURN in outputs, but this script relies on the full 'hex' field for large files. API may not support this download.")
                return None
    
    logger.error(f"Could not find a parsable OP_RETURN or full transaction hex for {txid}.")
    return None

def main():
    if len(sys.argv) != 2:
        print("Usage: python download_file.py <manifest_txid>")
        sys.exit(1)

    manifest_txid = sys.argv[1]
    
    # This function now does all the work of fetching and parsing.
    op_return_payload = find_and_parse_op_return_from_txid(manifest_txid)
    
    if op_return_payload is None:
        logger.error(f"Could not retrieve or parse OP_RETURN from manifest transaction {manifest_txid}.")
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
        logger.info("Found inlined Base64 data. Decoding...")
        try:
            file_content_bytes = base64.b64decode(manifest["data"])
        except Exception as e:
            logger.exception(f"Failed to decode Base64 data: {e}")
            sys.exit(1)
            
    elif "chunks" in manifest:
        chunk_txids = manifest.get("chunks", [])
        total_chunks = len(chunk_txids)
        logger.info(f"Found {total_chunks} data chunks. Reassembling file...")
        
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

    # Verify file size and save to disk
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