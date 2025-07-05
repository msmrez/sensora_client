# src/sensora_client/bsv_utils2.py

import logging
import struct
import threading
import math

from bsvlib import PrivateKey, Transaction, TxOutput
from bsvlib.script import Script
from . import config
from .bsv_utils import find_spendable_utxos, broadcast_transaction

logger = logging.getLogger(__name__)

def create_pushdata(data: bytes) -> bytes:
    data_len = len(data)
    if data_len <= 75: return bytes([data_len]) + data
    elif data_len <= 255: return b'\x4c' + bytes([data_len]) + data
    elif data_len <= 65535: return b'\x4d' + struct.pack('<H', data_len) + data
    else: return b'\x4e' + struct.pack('<I', data_len) + data

def estimate_hybrid_tx_fee(num_inputs: int, manifest_size: int, data_size: int) -> int:
    op_return_script_size = len(b'\x00\x6a') + len(create_pushdata(b"UPFV2")) + len(create_pushdata(b'A'*manifest_size)) + len(create_pushdata(b'A'*data_size))
    size = 10 + (num_inputs * 141) + op_return_script_size + 34 + 34
    return math.ceil(size * config.BSV_FEE_SATOSHIS_PER_BYTE_CONSUMER) or 1

def create_hybrid_op_return_tx(lock: threading.Lock, private_key: PrivateKey, manifest_bytes: bytes, data_bytes: bytes) -> str | None:
    with lock:
        try:
            funding_address = private_key.public_key().address()
            funding_script_hex = private_key.public_key().locking_script().hex()
            
            sats_needed = estimate_hybrid_tx_fee(1, len(manifest_bytes), len(data_bytes)) + config.SERVICE_FEE_SATS
            
            logger.info(f"Attempting hybrid upload for {funding_address}. Need ~{sats_needed} sats.")
            
            utxos, total_sats = find_spendable_utxos(funding_address, funding_script_hex, [private_key])
            if not utxos or total_sats < sats_needed:
                logger.warning(f"Insufficient funds. Have: {total_sats}, Need: {sats_needed}.")
                return None

            utxos.sort(key=lambda u: u.satoshi)
            selected_unspents = []
            sats_in_selected = 0
            for utxo in utxos:
                selected_unspents.append(utxo)
                sats_in_selected += utxo.satoshi
                # Re-estimate with actual number of inputs for better accuracy
                current_fee_estimate = estimate_hybrid_tx_fee(len(selected_unspents), len(manifest_bytes), len(data_bytes))
                if sats_in_selected >= (current_fee_estimate + config.SERVICE_FEE_SATS):
                    break
            
            UPFILE_V2_PREFIX = b"UPFV2"
            script_parts = [
                b'\x00\x6a',
                create_pushdata(UPFILE_V2_PREFIX),
                create_pushdata(manifest_bytes),
                create_pushdata(data_bytes)
            ]
            op_return_script = Script(b''.join(script_parts))
            
            tx = Transaction(tx_outputs=[TxOutput(out=op_return_script, satoshi=0)], fee_rate=config.BSV_FEE_SATOSHIS_PER_BYTE_CONSUMER)
            tx.add_inputs(selected_unspents)
            tx.add_change(change_address=funding_address)
            tx.sign()
            
            logger.info(f"Hybrid TX constructed. Fee: {tx.fee()} sats.")
            return broadcast_transaction(tx.raw())

        except Exception as e:
            logger.exception(f"Error creating hybrid OP_RETURN transaction: {e}")
            return None