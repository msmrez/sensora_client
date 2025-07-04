#!/usr/bin/env python3

import sys
import os
import logging
import json
import base64
import requests

# We still use the client's config for non-Bitails settings if needed in the future,
# but the API URL will be hardcoded here to avoid confusion.
from src.sensora_client import config
from bsvlib import Transaction

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(name)s] %(module)s.%(funcName)s - %(message)s')
logger = logging.getLogger(__name__)

def get_raw_tx_from_whatsonchain(txid: str) -> str | None:
    """
    Fetches the full, untruncated raw transaction hex from the WhatsOnChain API.
    This is our definitive source for large transaction data.
    """
    try:
        # This is the public, reliable endpoint for raw transaction hex data.
        url = f"https://api.whatsonchain.com/v1/bsv/main/tx/{txid}/hex"
        logger.info(f"Fetching full raw transaction from WhatsOnChain: {url}")
        response = requests.get(url, timeout=45) # Allow a long timeout for large transactions
        response.raise_for_status() # Will raise an error for 4xx/5xx status codes
        
        # WhatsOnChain returns the raw hex as plain text, not JSON
        raw_tx_hex = response.text
        if not raw_tx_hex or len(raw_tx_hex) < 10: # Basic sanity check
            logger.error(f"WhatsOnChain returned an empty or invalid raw hex for {txid}")
            return None
        return raw_tx_hex
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error fetching raw tx {txid} from WhatsOnChain: {http_err}")
        return None
    except Exception as e:
        logger.exception(f"Failed to get raw transaction {txid} from WhatsOnChain: {e}")
        return None

def find_and_parse_op_return_from_txid(txid: str) -> bytes | None:
    """
    Given a TXID, fetches the raw transaction from WhatsOnChain and parses its OP_RETURN.
    """
    raw_tx_hex = get_raw_tx_from_whatsonchain(txid)
    if not raw_tx_hex:
        return None
        
    try:
        # Use bsvlib to parse the raw transaction hex
        tx = Transaction.from_hex(raw_tx_hex)
        for output in tx.tx_outputs:
            if output.script.is_op_return():
                # .get_op_return() returns a list of all data pushes.
                # The UPFILE protocol uses a single push for its manifest and for each chunk.
                op_return_data_parts = output.script.get_op_return()
                if op_return_data_parts and isinstance(op_return_data_parts, list):
                    return op_return_data_parts[0]
        
        logger.warning(f"No OP_RETURN output found in transaction {txid}")
        return None
    except Exception as e:
        logger.exception(f"Failed to parse raw transaction hex for {txid}: {e}")
        return None

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
    
    # Handle inlined vs. chunked data
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