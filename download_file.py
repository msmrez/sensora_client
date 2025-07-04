#!/usr/bin/env python3

import sys
import os
import logging
import json
import base64
import requests

from src.sensora_client import config
from bsvlib import Transaction

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(name)s] %(module)s.%(funcName)s - %(message)s')
logger = logging.getLogger(__name__)

def get_raw_transaction_from_whatsonchain(txid: str) -> str | None:
    """
    Fetches the raw hex of a transaction from the WhatsOnChain API.
    This is our reliable source for untruncated transaction data.
    """
    try:
        # Use WhatsOnChain API specifically for this task
        url = f"https://api.whatsonchain.com/v1/bsv/main/tx/{txid}/hex"
        logger.info(f"Fetching raw transaction from WhatsOnChain: {url}")
        response = requests.get(url, timeout=30) # Allow longer timeout for potentially large tx
        response.raise_for_status()
        # WhatsOnChain returns the raw hex as plain text, not JSON
        return response.text
    except Exception as e:
        logger.exception(f"Failed to get raw transaction for txid {txid} from WhatsOnChain: {e}")
        return None

def find_and_parse_op_return_from_txid(txid: str) -> bytes | None:
    """
    Given a TXID, fetches the raw transaction from WhatsOnChain and parses its OP_RETURN.
    """
    raw_tx_hex = get_raw_transaction_from_whatsonchain(txid)
    if not raw_tx_hex:
        return None
        
    try:
        tx = Transaction.from_hex(raw_tx_hex)
        for output in tx.tx_outputs:
            if output.script.is_op_return():
                op_return_data = output.script.get_op_return()
                # bsvlib returns a list for OP_RETURNs with multiple pushes
                # The UPFILE manifest is a single data push
                if op_return_data and isinstance(op_return_data, list):
                    return op_return_data[0]
                return op_return_data # Fallback for single item
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
        file_content_bytes = base64.b64decode(manifest["data"])
    elif "chunks" in manifest:
        chunk_txids = manifest.get("chunks", [])
        total_chunks = len(chunk_txids)
        logger.info(f"Found {total_chunks} data chunks. Reassembling file...")
        
        reassembled_chunks = []
        for i, chunk_txid in enumerate(chunk_txids):
            logger.info(f"--> Fetching chunk {i+1}/{total_chunks} (TXID: {chunk_txid[:10]}...)")
            # We use the same reliable function to get each chunk's data
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