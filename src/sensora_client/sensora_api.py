# src/sensora_client/sensora_api.py

import requests
import logging
import time
import json
import hashlib
from bsvlib import PrivateKey

# We also need the bsv_utils from the original script
from sensora_client import bsv_utils

logger = logging.getLogger(__name__)

class SensoraAPI:
    """
    A Python class to interact with the Sensōra Network.
    Handles discovery, purchase, and verification of IoT data.
    """
    def __init__(self, indexer_url: str):
        """
        Initializes the API client with the URL of a Sensōra Indexer.
        """
        if not indexer_url.endswith('/'):
            indexer_url += '/'
        self.indexer_url = indexer_url
        logger.info(f"SensoraAPI initialized with indexer: {self.indexer_url}")

    def discover_best_sensor(self, data_type: int = 1) -> dict | None:
        """
        Finds the best available sensor for a given data type, sorted by reputation.
        """
        try:
            search_url = f"{self.indexer_url}api/v1/sensors/search?data_type={data_type}&sort=reputation"
            logger.info(f"Discovering sensors from registry: {search_url}")
            response = requests.get(search_url, timeout=10)
            response.raise_for_status()
            sensors = response.json()
            
            if not sensors:
                logger.warning("No online sensors found offering the requested data type.")
                return None
            
            selected_sensor = sensors[0]
            logger.info(f"Discovered sensor: {selected_sensor.get('device_id')}")
            return selected_sensor
        except Exception as e:
            logger.exception(f"Failed to discover sensors from registry: {e}")
            return None
        

    def purchase_reading(self, sensor: dict, reading_id: str, consumer_priv_key: PrivateKey):
        """
        Handles the entire single reading purchase flow and returns the verified data.
        """
        sensor_ipv6 = sensor.get('ipv6_address')
        sensor_port = sensor.get('port')
        sensor_api_base = f"http://[{sensor_ipv6}]:{sensor_port}"

        try:
            # 1. Get final price and payment address
            price_response = requests.get(f"{sensor_api_base}/price", timeout=5).json()
            device_payment_address = price_response['payment_address']
            price_sats = price_response['price_sats']

            # 2. Pay
            op_return_data = f"SENSORA_PAY:{reading_id}".encode('utf-8')
            payment_tx = bsv_utils.create_payment_transaction(consumer_priv_key, device_payment_address, price_sats, op_return_data)
            if not payment_tx: return None

            payment_txid = bsv_utils.broadcast_transaction(payment_tx.raw())
            if not payment_txid: return None
            
            logger.info(f"Payment broadcasted: {payment_txid}. Waiting a few seconds...")
            time.sleep(10)
            
            # 3. Claim
            claim_url = f"{sensor_api_base}/claim_reading/{reading_id}"
            claim_payload = {"payment_txid": payment_txid}
            response = requests.post(claim_url, json=claim_payload, timeout=10)
            response.raise_for_status()
            claim_response = response.json()
            access_token = claim_response['access_token']
            data_endpoint = claim_response['data_endpoint']
            logger.info("Token claimed successfully.")

            # 4. Fetch
            fetch_url = f"{sensor_api_base}{data_endpoint}?token={access_token}"
            data_response = requests.get(fetch_url, timeout=10)
            data_response.raise_for_status()
            purchased_data = data_response.json()
            
            logger.info("Data successfully retrieved.")

            # 5. Verify
            proof_txid = purchased_data.get('onchain_proof_txid')
            if not proof_txid:
                logger.warning("Agent did not provide a proof_txid. Returning unverified data.")
                return purchased_data

            is_verified = self._verify_data_integrity(purchased_data, proof_txid)
            if is_verified:
                return purchased_data
            else:
                logger.error("Verification failed! The data may have been tampered with.")
                return None

        except Exception as e:
            logger.exception(f"An error occurred during the single reading purchase flow: {e}")
            return None

    def purchase_batch(self, sensor: dict, start_ts: int, end_ts: int, consumer_priv_key: PrivateKey):
        """
        Handles the entire batch purchase flow and returns the verified data.
        """
        sensor_ipv6 = sensor.get('ipv6_address')
        sensor_port = sensor.get('port')
        sensor_api_base = f"http://[{sensor_ipv6}]:{sensor_port}"

        try:
            # 1. Get Quote
            price_url = f"{sensor_api_base}/batch/price"
            price_payload = {"start_timestamp": start_ts, "end_timestamp": end_ts}
            response = requests.post(price_url, json=price_payload, timeout=10)
            # ... (add your 413 and 404 status code checks here if you wish)
            response.raise_for_status()
            quote = response.json()
            logger.info(f"Agent Quote: {quote['num_readings']} readings for {quote['total_price_sats']} sats.")

            # (For a library, we might remove the interactive 'input' and assume confirmation)
            
            # 2. Pay
            batch_id = quote['batch_id']
            payment_txid = bsv_utils.broadcast_transaction(
                bsv_utils.create_payment_transaction(
                    consumer_priv_key, 
                    quote['payment_address'], 
                    quote['total_price_sats'], 
                    f"SENSORA_PAY:{batch_id}".encode('utf-8')
                ).raw()
            )
            if not payment_txid: return None
            
            logger.info(f"Payment broadcasted: {payment_txid}. Waiting a few seconds...")
            time.sleep(10)

            # 3. Claim
            claim_url = f"{sensor_api_base}/batch/claim"
            claim_payload = {"batch_id": batch_id, "payment_txid": payment_txid}
            claim_response = requests.post(claim_url, json=claim_payload, timeout=10)
            claim_response.raise_for_status()
            claim_data = claim_response.json()
            access_token = claim_data['access_token']
            data_endpoint = claim_data['data_endpoint']

            # 4. Fetch
            fetch_url = f"{sensor_api_base}{data_endpoint}?token={access_token}"
            data_response = requests.get(fetch_url, timeout=30)
            data_response.raise_for_status()
            batch_data = data_response.json()
            logger.info(f"Successfully downloaded batch of {len(batch_data)} readings.")

            # 5. Verify
            logger.info("--- Starting Verification of Batch Data ---")
            all_verified = True
            for i, reading in enumerate(batch_data, 1):
                proof_txid = reading.get('onchain_proof_txid')
                if proof_txid:
                    if not self._verify_data_integrity(reading, proof_txid):
                        all_verified = False
                else:
                    all_verified = False
            
            if all_verified:
                logger.info("✅ SUCCESS: All readings in the batch have been cryptographically verified!")
                return batch_data
            else:
                logger.error("🚨 WARNING: One or more readings in the batch failed verification.")
                return None # Or return the partially verified data with a flag

        except Exception as e:
            logger.exception(f"An error occurred during the batch purchase flow: {e}")
            return None

    def _verify_data_integrity(self, purchased_data: dict, proof_txid: str) -> bool:
        """
        Internal helper method to verify a single reading against its on-chain proof.
        (Note the leading underscore, indicating it's for internal class use).
        """
        # --- This is the exact same logic from your client.py's verify function ---
        timestamp = purchased_data.get('timestamp')
        temp_val = None
        humid_val = None

        if 'sensor_values' in purchased_data:
            temp_val, humid_val = purchased_data['sensor_values']
        elif 'value_temp' in purchased_data:
            temp_val = purchased_data.get('value_temp')
            humid_val = purchased_data.get('value_humid')
        
        if timestamp is None or temp_val is None or humid_val is None:
            logger.error("Verification failed: Data is missing required keys.")
            return False

        try:
            temp_str = f"{temp_val:.1f}"
            humidity_str = f"{humid_val:.1f}"
            data_to_hash_str = f"{timestamp}:{temp_str}:{humidity_str}"
            local_hash = hashlib.sha256(data_to_hash_str.encode('utf-8')).digest()
        except (ValueError, TypeError):
            logger.error("Verification failed: Could not format sensor values for hashing.")
            return False
        
        onchain_hash = bsv_utils.get_onchain_proof_hash(proof_txid)
        if not onchain_hash:
            logger.error("Could not retrieve the original data hash from the blockchain.")
            return False
        
        if local_hash == onchain_hash:
            logger.info(f"Verification successful for timestamp {timestamp}.")
            return True
        else:
            logger.error(f"Verification FAILED for timestamp {timestamp}. Hashes do not match!")
            logger.debug(f"  Local Hash: {local_hash.hex()}")
            logger.debug(f"  On-chain Hash: {onchain_hash.hex()}")
            return False

    # We will add the purchase_reading and purchase_batch methods here in the next steps.