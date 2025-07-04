# sensora_client/src/sensora_client/bsv_utils2.py

import logging
import struct
import threading

from bsvlib import PrivateKey, PublicKey, TxOutput, Unspent, Transaction
from bsvlib.script import Script

from . import config
# --- START FIX: Import the functions from the other utility module ---
from .bsv_utils import find_spendable_utxos, broadcast_transaction
# --- END FIX ---

logger = logging.getLogger(__name__)


def create_and_broadcast_op_return_tx(lock: threading.Lock, priv_key: PrivateKey, op_return_data: bytes) -> str | None:
    """Thread-safe function to create and broadcast a simple OP_RETURN transaction."""
    with lock:
        logger.info("[BSV_LOCK] Acquired transaction lock.")
        try:
            pub_key = priv_key.public_key()
            address = pub_key.address()
            locking_script = pub_key.locking_script().hex()

            estimated_tx_size = 148 + (9 + len(op_return_data)) + 34 + 10 
            min_fee_needed = int(estimated_tx_size * config.BSV_FEE_SATOSHIS_PER_BYTE_CONSUMER) or 1
            
            logger.info(f"Attempting to create OP_RETURN for {address}. Estimated fee: {min_fee_needed} sats.")
            
            # This call will now work because we imported the function.
            # It calls the find_spendable_utxos function from bsv_utils.py
            utxos, total_sats = find_spendable_utxos(address, locking_script, [priv_key])
            
            if not utxos or total_sats < min_fee_needed:
                logger.warning(f"Insufficient funds. Available: {total_sats}, Need: {min_fee_needed}.")
                return None

            # Coin selection
            utxos.sort(key=lambda u: u.satoshi)
            selected_unspents = []
            sats_in_selected = 0
            for utxo in utxos:
                selected_unspents.append(utxo)
                sats_in_selected += utxo.satoshi
                if sats_in_selected >= min_fee_needed: break
            
            if sats_in_selected < min_fee_needed:
                logger.error(f"Could not select enough UTXOs. Need: {min_fee_needed}, Selected: {sats_in_selected}")
                return None

            # Manual OP_RETURN script creation
            script_bytes_list = [b'\x00', b'\x6a']
            data_len = len(op_return_data)
            if data_len <= 75: script_bytes_list.append(bytes([data_len])) 
            elif data_len <= 255: script_bytes_list.extend([b'\x4c', bytes([data_len])]) 
            elif data_len <= 65535: script_bytes_list.extend([b'\x4d', struct.pack('<H', data_len)]) 
            else: script_bytes_list.extend([b'\x4e', struct.pack('<I', data_len)])
            script_bytes_list.append(op_return_data)
            op_return_script = Script(b''.join(script_bytes_list))
            
            # Create and finalize transaction
            tx = Transaction(tx_outputs=[TxOutput(out=op_return_script, satoshi=0)], fee_rate=config.BSV_FEE_SATOSHIS_PER_BYTE_CONSUMER)
            tx.add_inputs(selected_unspents)
            tx.add_change(change_address=address)
            tx.sign()
            
            final_fee = tx.fee()
            change_sats = sats_in_selected - final_fee
            logger.info(f"OP_RETURN TX constructed. Fee: {final_fee} sats. Change: {change_sats} sats.")
            
            # This call will also work now due to the import.
            return broadcast_transaction(tx.raw())
            
        except Exception as e:
            logger.exception(f"Error during OP_RETURN transaction creation: {e}")
            return None