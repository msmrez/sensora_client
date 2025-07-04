#!/usr/bin/env python3

import sys
import os
import mimetypes
import logging

# Import project modules
from src.sensora_client import config, bsv_utils
from bsvlib import PrivateKey, TxOutput, Transaction, Unspent
from bsvlib.script import Script

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- B Protocol Constants ---
B_PROTOCOL_PREFIX = "19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut"

def main():
    if len(sys.argv) != 3:
        print("Usage: python bigfile.py <path_to_file> <your_paying_wif>")
        sys.exit(1)

    file_path = sys.argv[1]
    wif_string = sys.argv[2]

    # 1. Validate inputs
    if not os.path.exists(file_path):
        logger.error(f"File not found at: {file_path}")
        sys.exit(1)

    try:
        private_key = PrivateKey(wif_string)
        public_key = private_key.public_key()
        funding_address = public_key.address()
        funding_script_hex = public_key.locking_script().hex()
        logger.info(f"Using wallet address: {funding_address}")
    except Exception as e:
        logger.error(f"Invalid WIF provided. Error: {e}")
        sys.exit(1)

    # 2. Read file content and determine metadata
    try:
        with open(file_path, 'rb') as f:
            file_content_bytes = f.read()
        
        file_size = len(file_content_bytes)
        # Guess MIME type, fallback to a generic binary type
        mime_type, _ = mimetypes.guess_type(file_path)
        if not mime_type:
            mime_type = "application/octet-stream"
        
        file_name = os.path.basename(file_path)
        
        logger.info(f"File: '{file_name}'")
        logger.info(f"Size: {file_size / 1024:.2f} KB")
        logger.info(f"MIME Type: {mime_type}")

    except Exception as e:
        logger.error(f"Failed to read file: {e}")
        sys.exit(1)

    # 3. Create the OP_RETURN outputs for the B protocol
    # B protocol format: <B_PREFIX> <content> <mime_type> <encoding> <filename>
    # We will push each part as a separate data element in the script.
    op_return_script_parts = [
        B_PROTOCOL_PREFIX.encode('utf-8'),
        file_content_bytes,
        mime_type.encode('utf-8'),
        b'binary',  # Or 'base64' if you encode it
        file_name.encode('utf-8')
    ]
    
    try:
        op_return_script = Script.from_op_return(op_return_script_parts)
    except Exception as e:
        logger.error(f"Failed to create OP_RETURN script, likely because the file is too large for a single push. Error: {e}")
        # Note: A single data push in Bitcoin script is limited to 4GB, but practical limits
        # from services like bitails.io might be much smaller (e.g., 100KB).
        # For very large files, a different protocol like B://CAT is needed to split the file.
        # This script assumes the file fits in a single OP_RETURN push.
        sys.exit(1)

    op_return_output = TxOutput(out=op_return_script, satoshi=0)
    
    # 4. Find UTXOs to pay for the transaction fee
    # The fee is based on the total transaction size, which is dominated by the file size.
    # Estimated size = (input size) + (output size) + (file size) + overhead
    estimated_tx_size = 200 + file_size 
    fee_needed = int(estimated_tx_size * config.BSV_FEE_SATOSHIS_PER_BYTE_CONSUMER) or 1
    logger.info(f"Estimated TX fee: {fee_needed} satoshis")

    utxos, total_sats = bsv_utils.find_spendable_utxos_for_consumer(funding_address, funding_script_hex, [private_key])
    if total_sats < fee_needed:
        logger.error(f"Insufficient funds. Wallet has {total_sats} sats, but fee requires ~{fee_needed} sats.")
        sys.exit(1)

    # Simple coin selection
    utxos.sort(key=lambda u: u.satoshi, reverse=True) # Use largest UTXO first
    selected_utxos = []
    sats_in_selected = 0
    for utxo in utxos:
        selected_utxos.append(utxo)
        sats_in_selected += utxo.satoshi
        if sats_in_selected >= fee_needed:
            break
            
    if sats_in_selected < fee_needed:
        logger.error("Could not select enough UTXOs to cover the fee.")
        sys.exit(1)

    # 5. Construct and sign the transaction
    try:
        tx = Transaction(tx_outputs=[op_return_output], fee_rate=config.BSV_FEE_SATOSHIS_PER_BYTE_CONSUMER)
        tx.add_inputs(selected_utxos)
        tx.add_change(change_address=funding_address)
        tx.sign()
        
        raw_tx_hex = tx.raw()
        final_fee = tx.fee()
        logger.info(f"Transaction constructed successfully!")
        logger.info(f"  Final TX Size: {len(raw_tx_hex) / 2 / 1024:.2f} KB")
        logger.info(f"  Final Fee: {final_fee} satoshis")

    except Exception as e:
        logger.exception(f"Error creating or signing the transaction: {e}")
        sys.exit(1)
        
    # 6. Save raw transaction to a file
    output_filename = "raw_tx_for_bigfile.txt"
    try:
        with open(output_filename, 'w') as f:
            f.write(raw_tx_hex)
        logger.info(f"Raw transaction hex saved to '{output_filename}'")
    except Exception as e:
        logger.error(f"Could not save raw tx to file: {e}")

    # 7. Attempt to broadcast
    logger.info("Attempting to broadcast the transaction...")
    txid = bsv_utils.broadcast_transaction(raw_tx_hex)
    
    if txid:
        logger.info(f"\n--- SUCCESS ---")
        logger.info(f"Transaction successfully broadcasted!")
        logger.info(f"TXID: {txid}")
        logger.info(f"View on bitails.io: https://bitails.io/tx/{txid}")
    else:
        logger.error(f"\n--- FAILURE ---")
        logger.error("Transaction broadcast failed. Check the logs above.")
        logger.error(f"You can try to broadcast the transaction manually using the content of '{output_filename}'.")

if __name__ == "__main__":
    # Add mimetypes for common types if needed
    mimetypes.add_type("image/webp", ".webp")
    main()