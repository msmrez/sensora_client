# sensora_client/src/sensora_client/bsv_utils.py

import requests
import json
import logging
import struct # <--- ADD THIS IMPORT
from bsvlib import PrivateKey, PublicKey, TxOutput, TxInput, Unspent, Transaction
from bsvlib.script import Script
from bsvlib.script.type import P2pkhScriptType

from . import config

logger = logging.getLogger(__name__)

def find_spendable_utxos_for_consumer(address_str, locking_script_hex, private_keys):
    # This function is correct.
    utxos_url = f"https://api.bitails.io/address/{address_str}/unspent"
    logger.info(f"Fetching UTXOs for consumer {address_str} from: {utxos_url}")
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
        logger.exception(f"Error finding UTXOs for consumer: {e}")
        return [], 0

def broadcast_transaction(raw_tx_hex: str) -> str | None:
    # This function is correct.
    broadcast_url = "https://api.bitails.io/tx/broadcast"
    headers = {"Content-Type": "application/json"}
    payload = {"raw": raw_tx_hex}
    logger.info(f"Broadcasting consumer TX: {raw_tx_hex[:60]}...")
    try:
        response = requests.post(broadcast_url, headers=headers, json=payload, timeout=15)
        response.raise_for_status()
        data = response.json()
        txid = data.get("txid")
        if txid:
            logger.info(f"Broadcast successful. TXID: {txid}")
            return txid
        else:
            logger.error(f"Broadcast failed or TXID not returned. Response: {data}")
            return None
    except Exception as e:
        logger.exception(f"Error broadcasting consumer TX: {e}")
        return None

def create_payment_transaction(consumer_priv_key, device_payment_address, price_sats, op_return_data):
    """Constructs the full payment transaction."""
    consumer_pub_key = consumer_priv_key.public_key()
    consumer_address = consumer_pub_key.address()
    consumer_script_hex = consumer_pub_key.locking_script().hex()

    estimated_fee = 250 # A safe estimate for a simple payment tx
    sats_needed = price_sats + estimated_fee
    utxos, total_sats = find_spendable_utxos_for_consumer(consumer_address, consumer_script_hex, [consumer_priv_key])
    
    if total_sats < sats_needed:
        logger.error(f"Insufficient funds. Need ~{sats_needed} sats, have {total_sats}.")
        return None

    # Coin selection (simple)
    utxos.sort(key=lambda u: u.satoshi)
    inputs = []
    input_sats = 0
    for utxo in utxos:
        inputs.append(utxo)
        input_sats += utxo.satoshi
        if input_sats >= sats_needed:
            break

    # Create payment output
    payment_output = TxOutput(out=device_payment_address, satoshi=price_sats)

    # --- START CORRECTION ---
    # Create OP_RETURN output using manual serialization
    try:
        if not isinstance(op_return_data, bytes):
            raise ValueError(f"op_return_data must be bytes, got {type(op_return_data)}")
        
        script_bytes_list = [b'\x00', b'\x6a']
        data_len = len(op_return_data)
        
        if data_len <= 75: script_bytes_list.append(bytes([data_len])) 
        elif data_len <= 255: script_bytes_list.extend([b'\x4c', bytes([data_len])]) 
        else:
            logger.error("OP_RETURN data too large for this simple client.")
            return None

        script_bytes_list.append(op_return_data)
        serialized_script_bytes = b''.join(script_bytes_list)
        op_return_script = Script(serialized_script_bytes)
    except Exception as e:
        logger.exception(f"Failed to create OP_RETURN script: {e}")
        return None
    # --- END CORRECTION ---
    
    op_return_output = TxOutput(out=op_return_script, satoshi=0)
    
    # Build transaction
    tx = Transaction(tx_inputs=inputs, tx_outputs=[payment_output, op_return_output], fee_rate=config.BSV_FEE_SATOSHIS_PER_BYTE_CONSUMER)
    tx.add_change(change_address=consumer_address)
    tx.sign()
    
    logger.info(f"Payment TX constructed. Fee: {tx.fee()} sats. Change: {tx.change()} sats.")
    return tx