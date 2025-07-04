#!/usr/bin/env python3

import sys
import os
import logging
import json
import base64
import requests

from src.sensora_client import config
# --- START CORRECTION: Correct the bsvlib import ---
from bsvlib import Transaction # We only need the Transaction class
# --- END CORRECTION ---

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_raw_transaction(txid: str) -> str | None:
    """Fetches the raw hex of a transaction."""
    try:
        url = f"{config.BITAILS_API_BASE_URL}/tx/{txid}/raw"
        logger.info(f"Fetching raw transaction: {url}")
        response = requests.get(url, timeout=20)
        response.raise_for_status()
        try:
            # Some APIs wrap it in JSON
            return response.json().get("rawtx")
        except json.JSONDecodeError:
            # Others return raw text
            return response.text
    except Exception as e:
        logger.exception(f"Failed to get raw transaction for txid {txid}: {e}")
        return None

def find_and_parse_op_return_from_txid(txid: str) -> bytes | None:
    """
    Given a TXID, fetches the raw transaction and parses its OP_RETURN.
    """
    raw_tx_hex = get_raw_transaction(txid)
    if not raw_tx_hex:
        return None
        
    try:
        # Use the Transaction class to parse the raw hex
        tx = Transaction.from_hex(raw_tx_hex)
        for output in tx.tx_outputs:
            if output.script.is_op_return():
                # .get_op_return() is a valid method on a Script object instance
                return output.script.get_op_return()
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
        logger.info(f"Found {len(chunk_txids)} data chunks. Reassembling file...")
        reassembled_chunks = []
        for i, chunk_txid in enumerate(chunk_txids):
            logger.info(f"--> Fetching chunk {i+1}/{len(chunk_txids)} (TXID: {chunk_txid[:10]}...)")
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