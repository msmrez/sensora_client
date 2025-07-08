# sensora_client/client.py

import requests
import time
import sys
import json
import logging
import hashlib


from src.sensora_client import config, bsv_utils
from bsvlib import PrivateKey

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def discover_sensor(data_type: int = 1):
    """Finds a sensor using the Registry API."""
    try:
        search_url = f"{config.REGISTRY_API_URL}/api/v1/sensors/search?data_type={data_type}"
        logger.info(f"Discovering sensors from registry: {search_url}")
        response = requests.get(search_url, timeout=10)
        response.raise_for_status()
        sensors = response.json()
        
        if not sensors:
            logger.warning("No online sensors found offering the requested data type.")
            return None
        
        # For this MVP, just select the first sensor found
        selected_sensor = sensors[0]
        logger.info(f"Discovered sensor: {selected_sensor.get('device_id')}")
        return selected_sensor
    except Exception as e:
        logger.exception(f"Failed to discover sensors from registry: {e}")
        return None

def purchase_reading(sensor: dict, reading_id: str, consumer_priv_key: PrivateKey):
    """Handles the entire purchase flow for a given reading."""
    
    # 1. Get required info from sensor profile
    sensor_ipv6 = sensor.get('ipv6_address')
    sensor_port = sensor.get('port')
    # This requires the sensor API to provide its payment address. Let's assume it does.
    # For now, we will fetch it from the /price endpoint.
    
    sensor_api_base = f"http://[{sensor_ipv6}]:{sensor_port}"
    
    # Get price and payment address
    try:
        price_response = requests.get(f"{sensor_api_base}/price", timeout=5).json()
        device_payment_address = price_response['payment_address']
        price_sats = price_response['price_sats']
    except Exception as e:
        logger.error(f"Failed to get price from sensor {sensor_ipv6}: {e}")
        return
        
    # 2. Construct and broadcast payment
    op_return_data = f"SENSORA_PAY:{reading_id}".encode('utf-8')
    payment_tx = bsv_utils.create_payment_transaction(consumer_priv_key, device_payment_address, price_sats, op_return_data)
    
    if not payment_tx:
        logger.error("Failed to create payment transaction.")
        return
        
    payment_txid = bsv_utils.broadcast_transaction(payment_tx.raw())
    if not payment_txid:
        logger.error("Failed to broadcast payment transaction.")
        return
        
    logger.info(f"Payment broadcasted: {payment_txid}. Waiting a few seconds to claim...")
    time.sleep(10)
    
    # 3. Claim token
    try:
        claim_url = f"{sensor_api_base}/claim_reading/{reading_id}"
        claim_payload = {"payment_txid": payment_txid}
        claim_response = requests.post(claim_url, json=claim_payload, timeout=10).json()
        access_token = claim_response['access_token']
        data_endpoint = claim_response['data_endpoint']
        logger.info(f"Token claimed successfully: {access_token[:8]}...")
    except Exception as e:
        logger.exception(f"Failed to claim token: {e}")
        return
        
    # 4. Fetch data with token
    try:
        fetch_url = f"{sensor_api_base}{data_endpoint}?token={access_token}"
        data_response = requests.get(fetch_url, timeout=10)
        data_response.raise_for_status()
        
        purchased_data_payload = data_response.json()
        
        print("\n--- PURCHASED DATA ---")
        # Print a cleaner version of the data for the user
        print(json.dumps({
            "timestamp": purchased_data_payload.get('timestamp'),
            "sensor_values": purchased_data_payload.get('sensor_values')
        }, indent=2))
        print("----------------------")
        logger.info("Data successfully purchased and retrieved!")

        # 5. --- NEW VERIFICATION STEP ---
        # Use the correct key from your agent's API response
        proof_txid = purchased_data_payload.get('onchain_proof_txid')
        if proof_txid:
            # Pass the whole payload to the verification function
            verify_data_integrity(purchased_data_payload, proof_txid)
        else:
            logger.warning("Agent did not provide a proof_txid. Cannot verify data integrity.")

    except Exception as e:
        logger.exception(f"Failed to fetch or verify data: {e}")



def verify_data_integrity(purchased_data: dict, proof_txid: str) -> bool:
    """Verifies the integrity of purchased data against its on-chain proof."""
    logger.info(f"Starting verification process for proof TXID: {proof_txid}")
    
    # 1. Recreate the exact string that was originally hashed by the agent
    # The agent's fetch_data response nests the values inside 'sensor_values'
    timestamp = purchased_data['timestamp']
    temp_val, humid_val = purchased_data['sensor_values']
    
    # Ensure precision matches the agent's hashing function (e.g., 1 decimal place)
    temp_str = f"{temp_val:.1f}"
    humidity_str = f"{humid_val:.1f}"
    
    data_to_hash_str = f"{timestamp}:{temp_str}:{humidity_str}"
    local_hash = hashlib.sha256(data_to_hash_str.encode('utf-8')).digest()
    
    logger.info(f"Locally calculated hash: {local_hash.hex()}")
    
    # 2. Get the original hash from the blockchain
    onchain_hash = bsv_utils.get_onchain_proof_hash(proof_txid)
    
    if not onchain_hash:
        logger.error("Could not retrieve the original data hash from the blockchain.")
        return False
        
    logger.info(f"On-chain hash found:   {onchain_hash.hex()}")
    
    # 3. Compare the hashes
    if local_hash == onchain_hash:
        logger.info("✅ SUCCESS: Data is authentic. Hashes match!")
        return True
    else:
        logger.error("🚨 FAILURE: Data tampering detected! Hashes DO NOT match.")
        return False


def main():
    if len(sys.argv) < 2:
        print("Usage: python client.py <YOUR_CONSUMER_WIF> [--reading-id <ID>] [--data-type <TYPE>]")
        sys.exit(1)
        
    consumer_wif = sys.argv[1]
    
    try:
        consumer_priv_key = PrivateKey(consumer_wif)
        logger.info(f"Consumer wallet loaded: {consumer_priv_key.public_key().address()}")
    except Exception as e:
        logger.error(f"Invalid consumer WIF provided: {e}")
        sys.exit(1)

    # Discover a sensor offering Temp/Humid data (type 1)
    # This part is now automated
    sensor_to_buy_from = discover_sensor(data_type=1)
    
    if not sensor_to_buy_from:
        logger.error("Could not find a suitable sensor. Exiting.")
        sys.exit(1)
        
    # Get the latest reading ID from the discovered sensor's /price endpoint
    try:
        price_url = f"http://[{sensor_to_buy_from['ipv6_address']}]:{sensor_to_buy_from['port']}/price"
        reading_id_to_buy = requests.get(price_url, timeout=5).json()['current_reading_id']
        logger.info(f"Found latest reading ID to purchase: {reading_id_to_buy}")
    except Exception as e:
        logger.error(f"Could not get latest reading ID from discovered sensor: {e}")
        sys.exit(1)
        
    purchase_reading(sensor_to_buy_from, reading_id_to_buy, consumer_priv_key)

if __name__ == "__main__":
    main()