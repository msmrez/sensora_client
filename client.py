# sensora_client/client.py

import argparse
import requests
import time
import sys
import json
import logging
import hashlib
import datetime


from src.sensora_client import config, bsv_utils
from bsvlib import PrivateKey

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def discover_sensor(data_type: int = 1):
    """Finds a sensor using the Registry API."""
    try:
        search_url = f"{config.REGISTRY_API_URL}/api/v1/sensors/search?data_type={data_type}&sort=reputation"        
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

# This is the full batch purchase function we designed earlier.
def purchase_batch(sensor: dict, start_ts: int, end_ts: int, consumer_priv_key: PrivateKey):
    """
    Handles the entire batch purchase flow: get price, confirm, pay, claim, fetch, and verify.
    """
    sensor_ipv6 = sensor.get('ipv6_address')
    sensor_port = sensor.get('port')
    sensor_api_base = f"http://[{sensor_ipv6}]:{sensor_port}"

    # 1. Get Price Quote from Agent
    logger.info(f"Requesting batch price quote from agent {sensor_ipv6}:{sensor_port}...")
    try:
        price_url = f"{sensor_api_base}/batch/price"
        price_payload = {"start_timestamp": start_ts, "end_timestamp": end_ts}
        response = requests.post(price_url, json=price_payload, timeout=10)

        if response.status_code == 413: # Handle batch size limit error
            error_data = response.json()
            logger.error("Request Failed: The agent rejected the request as too large.")
            logger.error(f"  Agent's Limit: {error_data.get('limit')} readings")
            logger.error(f"  You Requested: {error_data.get('requested')} readings")
            logger.error("Please try again with a shorter time range.")
            return

        if response.status_code == 404:
            logger.warning("Agent reported no readings found in the specified time range.")
            return

        response.raise_for_status()
        quote = response.json()
        logger.info(f"Agent Quote Received: {quote['num_readings']} readings for {quote['total_price_sats']} sats.")

    except requests.exceptions.HTTPError as e:
        logger.error(f"Failed to get batch price. Server responded with error: {e.response.status_code} {e.response.reason}")
        return
    except Exception as e:
        logger.exception(f"An error occurred while getting the batch price: {e}")
        return

    # 2. Get User Confirmation
    try:
        confirm = input(f"Proceed with payment of {quote['total_price_sats']} satoshis? [y/N]: ")
        if confirm.lower() != 'y':
            logger.info("Purchase cancelled by user.")
            return
    except KeyboardInterrupt:
        logger.info("\nPurchase cancelled by user.")
        return

    # 3. Construct and Broadcast Payment
    batch_id = quote['batch_id']
    payment_address = quote['payment_address']
    total_price = quote['total_price_sats']
    
    op_return_data = f"SENSORA_PAY:{batch_id}".encode('utf-8')
    payment_tx = bsv_utils.create_payment_transaction(consumer_priv_key, payment_address, total_price, op_return_data)
    if not payment_tx: return

    payment_txid = bsv_utils.broadcast_transaction(payment_tx.raw())
    if not payment_txid: return
    
    logger.info(f"Payment broadcasted: {payment_txid}. Waiting for propagation...")
    time.sleep(10)

    # 4. Claim Batch and Fetch Data
    try:
        claim_url = f"{sensor_api_base}/batch/claim"
        claim_payload = {"batch_id": batch_id, "payment_txid": payment_txid}
        claim_response = requests.post(claim_url, json=claim_payload, timeout=10).json()
        access_token = claim_response['access_token']
        data_endpoint = claim_response['data_endpoint']
        logger.info("Batch claim successful. Fetching data...")

        fetch_url = f"{sensor_api_base}{data_endpoint}?token={access_token}"
        data_response = requests.get(fetch_url, timeout=30)
        data_response.raise_for_status()
        batch_data = data_response.json()
        
        logger.info(f"Successfully downloaded batch of {len(batch_data)} readings.")

    except Exception as e:
        logger.exception(f"Failed to claim or fetch batch data: {e}")
        return
    
    # 5. Verify Each Reading in the Batch
    logger.info("--- Starting Verification of Batch Data ---")
    all_verified = True
    for i, reading in enumerate(batch_data, 1):
        proof_txid = reading.get('onchain_proof_txid')
        logger.info(f"Verifying reading #{i} of {len(batch_data)} (Timestamp: {reading['timestamp']})")
        if proof_txid:
            if not verify_data_integrity(reading, proof_txid):
                all_verified = False
        else:
            logger.warning(f"  - Reading {reading['timestamp']} is missing a proof TXID. Cannot verify.")
            all_verified = False
    
    logger.info("--- Verification Complete ---")
    if all_verified:
        logger.info("✅ SUCCESS: All readings in the batch have been cryptographically verified!")
    else:
        logger.error("🚨 WARNING: One or more readings in the batch failed verification.")


def main():
    parser = argparse.ArgumentParser(description="A smart client to purchase data from the Sensōra Network.")
    parser.add_argument("wif", help="The WIF (Wallet Import Format) private key of the consumer.")
    parser.add_argument("--type", type=int, default=1, help="The data type code to purchase (default: 1 for Temp/Humid).")
    
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--latest", action="store_true", help="Purchase the single latest reading (default behavior).")
    group.add_argument("--batch", action="store_true", help="Purchase a batch of historical readings.")

    parser.add_argument("--start", help="Start date for batch purchase (YYYY-MM-DD). Required with --batch.")
    parser.add_argument("--end", help="End date for batch purchase (YYYY-MM-DD). Required with --batch.")

    args = parser.parse_args()

    if args.batch and (not args.start or not args.end):
        parser.error("--start and --end are required when using --batch.")

    try:
        consumer_priv_key = PrivateKey(args.wif)
        logger.info(f"Consumer wallet loaded: {consumer_priv_key.public_key().address()}")
    except Exception:
        logger.exception("Invalid consumer WIF provided.")
        sys.exit(1)

    logger.info(f"Searching for the best sensor offering data type '{args.type}'...")
    sensor = discover_sensor(data_type=args.type)
    if not sensor:
        logger.error("Could not find a suitable sensor. Exiting.")
        sys.exit(1)

    if args.batch:
        logger.info("--- Initiating Batch Purchase Flow ---")
        try:
            start_ts = int(datetime.datetime.strptime(args.start, "%Y-%m-%d").timestamp())
            end_ts = int(datetime.datetime.strptime(args.end, "%Y-%m-%d").timestamp())
            # The purchase_batch function already contains the confirmation prompt
            purchase_batch(sensor, start_ts, end_ts, consumer_priv_key)
        except ValueError:
            logger.error("Invalid date format. Please use YYYY-MM-DD.")
            sys.exit(1)
    else:
        logger.info("--- Initiating Single Reading Purchase Flow ---")
        try:
            # --- START OF RESTORED CONFIRMATION LOGIC ---
            price_url = f"http://[{sensor['ipv6_address']}]:{sensor['port']}/price"
            price_info = requests.get(price_url, timeout=5).json()
            reading_id_to_buy = price_info['current_reading_id']
            price_sats = price_info['price_sats']

            logger.info(f"Sensor selected: {sensor['ipv6_address']}:{sensor['port']}")
            logger.info(f"    Price: {price_sats} sats")
            logger.info(f"    Reading ID: {reading_id_to_buy}")

            confirm = input("Proceed with purchase? [y/N]: ")
            if confirm.lower() != 'y':
                logger.info("Purchase cancelled by user.")
                sys.exit(0)
            
            # --- END OF RESTORED CONFIRMATION LOGIC ---

            # Now call the purchase function
            purchase_reading(sensor, reading_id_to_buy, consumer_priv_key)
        except Exception as e:
            logger.error(f"Could not get purchase details from discovered sensor: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()