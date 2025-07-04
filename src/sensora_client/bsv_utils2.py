# sensora_client/src/sensora_client/bsv_utils2.py

import requests
import json
import logging
import struct
import threading

from bsvlib import PrivateKey, PublicKey, TxOutput, TxInput, Unspent, Transaction
from bsvlib.script import Script
from bsvlib.script.type import P2pkhScriptType

from . import config
# This is the ONLY line that needs to be added to your original file
from .bsv_utils import find_spendable_utxos_for_consumer, broadcast_transaction

logger = logging.getLogger(__name__)

# --- UTXO and Broadcast Functions ---

def find_spendable_utxos(address_str: str, locking_script_hex: str, private_keys: list[PrivateKey]) -> tuple[list[Unspent], int]:
    """Finds all spendable UTXOs for a given address."""
    utxos_url = f"https://api.bitails.io/address/{address_str}/unspent"
    logger.info(f"Fetching UTXOs for {address_str} from: {utxos_url}")
    try:
        response = requests.get(utxos_url, timeout=10)
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
    """Broadcasts a raw transaction hex."""
    broadcast_url = "https://api.bitails.io/tx/broadcast"
    headers = {"Content-Type": "application/json"}
    payload = {"raw": raw_tx_hex}
    logger.info(f"Broadcasting TX: {raw_tx_hex[:60]}...")
    try:
        response = requests.post(broadcast_url, headers=headers, json=payload, timeout=15)
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

# --- Transaction Creation Functions ---

def create_payment_transaction(consumer_priv_key: PrivateKey, device_payment_address: str, price_sats: int, op_return_data: bytes) -> Transaction | None:
    """Constructs a payment transaction (P2PKH + OP_RETURN)."""
    consumer_pub_key = consumer_priv_key.public_key()
    consumer_address = consumer_pub_key.address()
    consumer_script_hex = consumer_pub_key.locking_script().hex()

    estimated_fee = 250
    sats_needed = price_sats + estimated_fee
    utxos, total_sats = find_spendable_utxos(consumer_address, consumer_script_hex, [consumer_priv_key])
    
    if total_sats < sats_needed:
        logger.error(f"Insufficient funds. Need ~{sats_needed} sats, have {total_sats}.")
        return None

    utxos.sort(key=lambda u: u.satoshi)
    selected_unspents: list[Unspent] = []
    sats_in_selected = 0
    for utxo in utxos:
        selected_unspents.append(utxo)
        sats_in_selected += utxo.satoshi
        if sats_in_selected >= sats_needed:
            break

    payment_output = TxOutput(out=device_payment_address, satoshi=price_sats)
    
    try:
        script_bytes_list = [b'\x00', b'\x6a']
        data_len = len(op_return_data)
        if data_len <= 75: script_bytes_list.append(bytes([data_len]))
        else: logger.error("OP_RETURN data too large."); return None
        script_bytes_list.append(op_return_data)
        op_return_script = Script(b''.join(script_bytes_list))
    except Exception as e:
        logger.exception(f"Failed to create OP_RETURN script: {e}"); return None
    
    op_return_output = TxOutput(out=op_return_script, satoshi=0)
    
    tx = Transaction(tx_outputs=[payment_output, op_return_output], fee_rate=config.BSV_FEE_SATOSHIS_PER_BYTE_CONSUMER)
    tx.add_inputs(selected_unspents)
    tx.add_change(change_address=consumer_address)
    tx.sign()
    
    final_fee = tx.fee()
    change_sats = sats_in_selected - price_sats - final_fee
    logger.info(f"Payment TX constructed. Fee: {final_fee} sats. Change: {change_sats} sats.")
    return tx

def create_and_broadcast_op_return_tx(lock: threading.Lock, priv_key: PrivateKey, op_return_data: bytes) -> str | None:
    """Thread-safe function to create and broadcast a simple OP_RETURN transaction."""
    with lock:
        logger.info("[BSV_LOCK] Acquired transaction lock.")
        pub_key = priv_key.public_key()
        address = pub_key.address()
        locking_script = pub_key.locking_script().hex()

        estimated_tx_size = 148 + (9 + len(op_return_data)) + 34 + 10 
        min_fee_needed = int(estimated_tx_size * config.BSV_FEE_SATOSHIS_PER_BYTE_CONSUMER) or 1
        
        logger.info(f"Attempting to create OP_RETURN for {address}. Estimated fee: {min_fee_needed} sats.")
        
        utxos, total_sats = find_spendable_utxos(address, locking_script, [priv_key])
        if not utxos or total_sats < min_fee_needed:
            logger.warning(f"Insufficient funds. Available: {total_sats}, Need: {min_fee_needed}.")
            return None

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

        try:
            script_bytes_list = [b'\x00', b'\x6a']
            data_len = len(op_return_data)
            if data_len <= 75: script_bytes_list.append(bytes([data_len])) 
            elif data_len <= 255: script_bytes_list.extend([b'\x4c', bytes([data_len])]) 
            elif data_len <= 65535: script_bytes_list.extend([b'\x4d', struct.pack('<H', data_len)]) 
            else: script_bytes_list.extend([b'\x4e', struct.pack('<I', data_len)])
            script_bytes_list.append(op_return_data)
            op_return_script = Script(b''.join(script_bytes_list))
            
            tx = Transaction(tx_outputs=[TxOutput(out=op_return_script, satoshi=0)], fee_rate=config.BSV_FEE_SATOSHIS_PER_BYTE_CONSUMER)
            tx.add_inputs(selected_unspents)
            tx.add_change(change_address=address)
            tx.sign()
            
            final_fee = tx.fee()
            change_sats = sats_in_selected - final_fee
            logger.info(f"OP_RETURN TX constructed. Fee: {final_fee} sats. Change: {change_sats} sats.")
            
            return broadcast_transaction(tx.raw())
        except Exception as e:
            logger.exception(f"Error during OP_RETURN transaction creation: {e}")
            return None