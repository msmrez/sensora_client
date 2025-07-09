# sensora_client/src/sensora_client/bsv_utils.py

import requests
import json
import logging
import struct # <--- ADD THIS IMPORT
from bsvlib import PrivateKey, PublicKey, TxOutput, TxInput, Unspent, Transaction
from bsvlib.script import Script
from bsvlib.script.type import P2pkhScriptType
import hashlib
import requests
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


def get_onchain_proof_hash(proof_txid: str) -> bytes | None:
    """Fetches a SENSORA_PROOF tx and extracts the data hash from its OP_RETURN."""
    try:
        url = f"https://api.bitails.io/tx/{proof_txid}"
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        tx_data = response.json()
        
        for output in tx_data.get('outputs', []):
            script_hex = output.get('script', '')
            # Check for OP_FALSE OP_RETURN
            if not script_hex.startswith("006a"):
                continue

            # Manually parse the payload from the script hex
            script_bytes = bytes.fromhex(script_hex)
            opcode = script_bytes[2]
            
            data_start_index = 0
            if 0x01 <= opcode <= 0x4b: data_start_index = 3
            elif opcode == 0x4c: data_start_index = 4
            elif opcode == 0x4d: data_start_index = 5
            else: continue # Unsupported push opcode
            
            payload = script_bytes[data_start_index:]
            
            # Now, check if this payload is a SENSORA_PROOF
            # Make sure this prefix matches your agent's config
            proof_prefix = b'SENSORA_PROOF' 
            if payload.startswith(proof_prefix):
                # The data hash is the last 32 bytes of the payload
                # Let's verify the expected length based on the protocol definition
                # Prefix(13) + Ver(1) + Type(1) + DevID(16) + ReadID(8) + DataType(2) + Hash(32) = 73 bytes
                if len(payload) == 73:
                    return payload[-32:] # Return the 32-byte hash
                
        return None # No valid proof found in any output
    except Exception:
        logger.exception(f"Error fetching or parsing proof transaction {proof_txid}")
        return None

def create_payment_transaction(consumer_priv_key: PrivateKey, device_payment_address: str, price_sats: int, op_return_data: bytes) -> Transaction | None:
    """Constructs the full payment transaction for the consumer."""
    try:
        consumer_pub_key = consumer_priv_key.public_key()
        consumer_address = consumer_pub_key.address()
        consumer_script_hex = consumer_pub_key.locking_script().hex()
    except Exception as e:
        logger.exception(f"Error deriving keys from provided WIF: {e}")
        return None

    # Find UTXOs for the consumer
    estimated_fee = 250  # A safe estimate in sats for a simple payment tx
    sats_needed = price_sats + estimated_fee
    utxos, total_sats = find_spendable_utxos_for_consumer(consumer_address, consumer_script_hex, [consumer_priv_key])
    
    if total_sats < sats_needed:
        logger.error(f"Insufficient funds. Need ~{sats_needed} sats, have {total_sats}.")
        return None

    # Coin selection (simple greedy algorithm)
    utxos.sort(key=lambda u: u.satoshi)
    selected_unspents: list[Unspent] = []
    sats_in_selected = 0
    for utxo in utxos:
        selected_unspents.append(utxo)
        sats_in_selected += utxo.satoshi
        if sats_in_selected >= sats_needed:
            break
    
    # This check is important in case the loop finishes without enough sats
    if sats_in_selected < sats_needed:
        logger.error(f"Could not select enough UTXOs after sorting. Selected: {sats_in_selected}, Need: {sats_needed}")
        return None

    # --- Create Transaction Outputs ---

    # 1. Create payment output to the sensor device
    try:
        payment_output = TxOutput(out=device_payment_address, satoshi=price_sats)
    except Exception as e:
        logger.exception(f"Failed to create P2PKH output for address {device_payment_address}: {e}")
        return None

    # 2. Create OP_RETURN output
    try:
        script_bytes_list = [b'\x00', b'\x6a'] # OP_FALSE OP_RETURN
        data_len = len(op_return_data)
        if op_return_data:
        # --- THIS IS THE CORRECTED CHECK ---
            if len(op_return_data) > config.OP_RETURN_MAX_SIZE:
                logger.error(f"OP_RETURN data is too large ({len(op_return_data)} bytes). Limit is {OP_RETURN_MAX_SIZE} bytes.")
                return None

        script_bytes_list.append(bytes([data_len]))
        script_bytes_list.append(op_return_data)
        op_return_script = Script(b''.join(script_bytes_list))
    except Exception as e:
        logger.exception(f"Failed to create OP_RETURN script: {e}")
        return None
    
    op_return_output = TxOutput(out=op_return_script, satoshi=0)
    
    # --- Build, Sign, and Finalize Transaction ---
    try:
        # Initialize transaction with outputs
        tx = Transaction(tx_outputs=[payment_output, op_return_output], fee_rate=config.BSV_FEE_SATOSHIS_PER_BYTE_CONSUMER)
        
        # Use the .add_inputs() method which correctly handles Unspent objects
        tx.add_inputs(selected_unspents)
        
        # Add a change output back to the consumer
        tx.add_change(change_address=consumer_address)
        
        # Sign the transaction
        tx.sign()
        
        # --- FINAL CORRECTED LOGGING ---
        final_fee = tx.fee()
        # Manually calculate change for logging, as .change() does not exist
        change_sats = sats_in_selected - price_sats - final_fee
        logger.info(f"Payment TX constructed. Fee: {final_fee} sats. Change: {change_sats} sats.")
        # --- END CORRECTION ---

        return tx
    except Exception as e:
        logger.exception(f"FATAL: Error during final transaction construction or signing: {e}")
        return None
    """Constructs the full payment transaction."""
    consumer_pub_key = consumer_priv_key.public_key()
    consumer_address = consumer_pub_key.address()
    consumer_script_hex = consumer_pub_key.locking_script().hex()

    estimated_fee = 250
    sats_needed = price_sats + estimated_fee
    utxos, total_sats = find_spendable_utxos_for_consumer(consumer_address, consumer_script_hex, [consumer_priv_key])
    
    if total_sats < sats_needed:
        logger.error(f"Insufficient funds. Need ~{sats_needed} sats, have {total_sats}.")
        return None

    # Coin selection
    utxos.sort(key=lambda u: u.satoshi)
    selected_unspents: list[Unspent] = []
    input_sats = 0
    for utxo in utxos:
        selected_unspents.append(utxo)
        input_sats += utxo.satoshi
        if input_sats >= sats_needed:
            break

    # Create payment output
    payment_output = TxOutput(out=device_payment_address, satoshi=price_sats)

    # Create OP_RETURN output
    try:
        script_bytes_list = [b'\x00', b'\x6a']
        data_len = len(op_return_data)
        if data_len <= 75: script_bytes_list.append(bytes([data_len]))
        else:
            logger.error("OP_RETURN data too large for this client.")
            return None
        script_bytes_list.append(op_return_data)
        serialized_script_bytes = b''.join(script_bytes_list)
        op_return_script = Script(serialized_script_bytes)
    except Exception as e:
        logger.exception(f"Failed to create OP_RETURN script: {e}")
        return None
    
    op_return_output = TxOutput(out=op_return_script, satoshi=0)
    
    tx = Transaction(tx_outputs=[payment_output, op_return_output], fee_rate=config.BSV_FEE_SATOSHIS_PER_BYTE_CONSUMER)
    
    # The .add_inputs() method is specifically designed to handle a list of Unspent objects.
    tx.add_inputs(selected_unspents)
    # --- END FINAL CORRECTION ---
    
    tx.add_change(change_address=consumer_address)
    tx.sign() # The keys are already in the Unspent objects, so sign() will use them.
    
    logger.info(f"Payment TX constructed. Fee: {tx.fee()} sats. Change: {tx.change()} sats.")
    return tx
    """Constructs the full payment transaction."""
    consumer_pub_key = consumer_priv_key.public_key()
    consumer_address = consumer_pub_key.address()
    consumer_script_hex = consumer_pub_key.locking_script().hex()

    estimated_fee = 250
    sats_needed = price_sats + estimated_fee
    utxos, total_sats = find_spendable_utxos_for_consumer(consumer_address, consumer_script_hex, [consumer_priv_key])
    
    if total_sats < sats_needed:
        logger.error(f"Insufficient funds. Need ~{sats_needed} sats, have {total_sats}.")
        return None

    # Coin selection (simple)
    utxos.sort(key=lambda u: u.satoshi)
    selected_unspents: list[Unspent] = []
    input_sats = 0
    for utxo in utxos:
        selected_unspents.append(utxo)
        input_sats += utxo.satoshi
        if input_sats >= sats_needed:
            break

    # --- START CORRECTION ---
    # Manually convert Unspent objects to TxInput objects.
    # The TxInput constructor takes an Unspent object via the 'utxo' parameter.
    tx_inputs = [TxInput(utxo=u) for u in selected_unspents]
    # --- END CORRECTION ---

    # Create payment output
    payment_output = TxOutput(out=device_payment_address, satoshi=price_sats)

    # Create OP_RETURN output
    try:
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
    
    op_return_output = TxOutput(out=op_return_script, satoshi=0)
    
    # Build transaction using the newly created TxInput list
    tx = Transaction(tx_inputs=tx_inputs, tx_outputs=[payment_output, op_return_output], fee_rate=config.BSV_FEE_SATOSHIS_PER_BYTE_CONSUMER)
    # The add_inputs method also expects TxInput objects, so tx_inputs is correct here if used instead of constructor
    # tx.add_inputs(tx_inputs) 
    tx.add_change(change_address=consumer_address)
    tx.sign()

    final_fee = tx.fee()
    # Manually calculate change for logging purposes
    change_sats = sats_in_selected - price_sats - final_fee
    logger.info(f"Payment TX constructed. Fee: {final_fee} sats. Change: {change_sats} sats.")
    # --- END CORRECTION ---

    logger.info(f"Payment TX constructed. Fee: {tx.fee()} sats. Change: {tx.change()} sats.")
    return tx
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