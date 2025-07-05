#!/usr/bin/env python3

import sys
import os
import mimetypes
import logging
import json
import base64
import requests
import struct
from typing import List

# All necessary bsvlib classes are imported here
from bsvlib import PrivateKey, Unspent, Transaction, TxOutput
from bsvlib.script import Script
from bsvlib.script.type import P2pkhScriptType

# --- Configuration (Self-Contained) ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

BITAILS_API_BASE_URL = "https://api.bitails.io"
BSV_FEE_RATE_SATS_PER_BYTE = 0.1
# Files larger than this will be rejected by this script, as they won't fit in one transaction.
FILE_SIZE_LIMIT = 9800 * 1024 # 98KB is a safe limit for a single OP_RETURN

# --- Helper Functions (Self-Contained) ---

def find_spendable_utxos(address: str, locking_script_hex: str, private_keys: list[PrivateKey]) -> tuple[list[Unspent], int]:
    """Finds all spendable UTXOs for a given address from bitails.io."""
    utxos_url = f"{BITAILS_API_BASE_URL}/address/{address}/unspent"
    logger.info(f"Fetching UTXOs for {address}...")
    try:
        response = requests.get(utxos_url, timeout=15)
        response.raise_for_status()
        data = response.json()
        if "unspent" not in data or not isinstance(data["unspent"], list):
            return [], 0
        
        parsed_unspents = []
        total_sats = 0
        for utxo_data in data["unspent"]:
            unspent_obj = Unspent(
                txid=utxo_data['txid'], vout=int(utxo_data['vout']),
                script_pubkey_hex=locking_script_hex, 
                satoshi=int(utxo_data.get('satoshis', 0)),
                script_type=P2pkhScriptType(), 
                private_keys=private_keys
            )
            parsed_unspents.append(unspent_obj)
            total_sats += unspent_obj.satoshi
        return parsed_unspents, total_sats
    except Exception as e:
        logger.exception(f"Error finding UTXOs: {e}")
        return [], 0

def broadcast_transaction(raw_tx_hex: str) -> str | None:
    """Broadcasts a raw transaction hex via bitails.io."""
    broadcast_url = f"{BITAILS_API_BASE_URL}/tx/broadcast"
    headers = {"Content-Type": "application/json"}
    payload = {"raw": raw_tx_hex}
    logger.info(f"Broadcasting TX ({len(raw_tx_hex)/2/1024:.2f} KB)...")
    try:
        response = requests.post(broadcast_url, headers=headers, json=payload, timeout=20)
        response.raise_for_status()
        data = response.json()
        txid = data.get("txid")
        if txid:
            logger.info(f"Broadcast successful. TXID: {txid}")
            return txid
        else:
            logger.error(f"Broadcast failed. Response: {data}")
            return None
    except Exception as e:
        logger.exception(f"Error broadcasting TX: {e}")
        return None

def create_pushdata(data: bytes) -> bytes:
    """Creates a valid Bitcoin Script PUSHDATA chunk for a given piece of data."""
    data_len = len(data)
    if data_len <= 75:
        return bytes([data_len]) + data
    elif data_len <= 255:
        return b'\x4c' + bytes([data_len]) + data
    elif data_len <= 65535:
        return b'\x4d' + struct.pack('<H', data_len) + data
    else: # PUSHDATA4
        return b'\x4e' + struct.pack('<I', data_len) + data

# --- Main Application Logic ---

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
        if file_size > FILE_SIZE_LIMIT:
            logger.error(f"File size ({file_size} bytes) exceeds the single transaction limit of {FILE_SIZE_LIMIT} bytes.")
            logger.error("This script is for single-transaction uploads. Please use a smaller file.")
            sys.exit(1)

        mime_type, _ = mimetypes.guess_type(file_path)
        if not mime_type: mime_type = "application/octet-stream"
        file_name = os.path.basename(file_path)
        
        logger.info(f"File: '{file_name}' ({mime_type}), Size: {file_size / 1024:.2f} KB")
    except Exception as e:
        logger.error(f"Failed to read file: {e}"); sys.exit(1)

    # 2. Create the hybrid UPFILE V2 manifest and script
    manifest = {
        "version": 2, "filename": file_name, "mime": mime_type,
        "size": file_size, "description": "Hybrid upload via Sensora"
    }
    manifest_bytes = json.dumps(manifest).encode('utf-8')
    
    UPFILE_V2_PREFIX = b"UPFV2"
    script_parts = [
        b'\x00\x6a', # OP_FALSE OP_RETURN
        create_pushdata(UPFILE_V2_PREFIX),
        create_pushdata(manifest_bytes),
        create_pushdata(file_content_bytes)
    ]
    op_return_script = Script(b''.join(script_parts))
    op_return_output = TxOutput(out=op_return_script, satoshi=0)

    # 3. Find UTXOs to cover the fee
    op_return_size = len(op_return_script.hex()) // 2
    est_fee = int((10 + 141 + op_return_size + 34) * BSV_FEE_RATE_SATS_PER_BYTE) or 1
    
    logger.info(f"Attempting hybrid upload. Estimated fee: {est_fee} sats.")
    
    utxos, total_sats = find_spendable_utxos(funding_address, funding_script_hex, [private_key])
    if not utxos or total_sats < est_fee:
        logger.error(f"Insufficient funds. Have: {total_sats}, Need at least: {est_fee} sats.")
        sys.exit(1)

    # 4. Construct, sign, and broadcast the transaction
    try:
        tx = Transaction(tx_outputs=[op_return_output], fee_rate=BSV_FEE_RATE_SATS_PER_BYTE)
        tx.add_inputs(utxos) # Use all available UTXOs for simplicity, bsvlib will select
        tx.add_change(change_address=funding_address)
        tx.sign()
        
        raw_tx_hex = tx.raw()
        final_fee = tx.fee()
        logger.info(f"Transaction constructed. Final Fee: {final_fee} satoshis.")
        
    except Exception as e:
        logger.exception(f"Error creating or signing the transaction: {e}")
        sys.exit(1)
        
    # 5. Save raw transaction to a file
    output_filename = "raw_tx_for_bigfile.txt"
    try:
        with open(output_filename, 'w') as f:
            f.write(raw_tx_hex)
        logger.info(f"Raw transaction hex saved to '{output_filename}'")
    except Exception as e:
        logger.error(f"Could not save raw tx to file: {e}")

    # 6. Attempt to broadcast
    txid = broadcast_transaction(raw_tx_hex)
    
    if txid:
        logger.info(f"\n--- UPLOAD COMPLETE ---")
        logger.info(f"Final Manifest TXID: {txid}")
        logger.info(f"View on bitails.io: https://bitails.io/tx/{txid}")
    else:
        logger.error(f"\n--- UPLOAD FAILED ---")

if __name__ == "__main__":
    main()