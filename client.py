# client.py - The new, simplified Command-Line Interface

import argparse
import sys
import logging
import requests
import datetime
import json
from bsvlib import PrivateKey

from sensora_client.sensora_api import SensoraAPI
from sensora_client import config, bsv_utils

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(description="A smart client to purchase data from the Sensōra Network.")
    parser.add_argument("wif", help="The WIF (Wallet Import Format) private key of the consumer.")
    parser.add_argument("--type", type=int, default=1, help="The data type code to purchase (default: 1).")
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
        logger.exception("Invalid consumer WIF provided."); sys.exit(1)

    # --- 1. Instantiate and use the API class ---
    api = SensoraAPI(indexer_url=config.REGISTRY_API_URL)
    
    logger.info(f"Searching for the best sensor offering data type '{args.type}'...")
    sensor = api.discover_best_sensor(data_type=args.type)
    if not sensor:
        logger.error("Could not find a suitable sensor. Exiting."); sys.exit(1)

    # --- 2. Handle Batch vs. Single Purchase ---
    if args.batch:
        logger.info("--- Initiating Batch Purchase Flow ---")
        try:
            start_ts = int(datetime.datetime.strptime(args.start, "%Y-%m-%d").timestamp())
            end_ts = int(datetime.datetime.strptime(args.end, "%Y-%m-%d").timestamp())
            
            # The API class handles the quote and confirmation internally,
            # but for a CLI, interactive confirmation is good. We'll add it back.
            # (For now, let's assume the library call is non-interactive)
            batch_data = api.purchase_batch(sensor, start_ts, end_ts, consumer_priv_key)
            
            if batch_data:
                print("\n--- BATCH PURCHASE COMPLETE ---")
                print(f"Successfully downloaded and verified {len(batch_data)} readings.")
            else:
                logger.error("Batch purchase failed. Please check logs for details.")

        except ValueError:
            logger.error("Invalid date format. Please use YYYY-MM-DD."); sys.exit(1)
    else: # Default to latest single reading
        logger.info("--- Initiating Single Reading Purchase Flow ---")
        try:
            price_url = f"http://[{sensor['ipv6_address']}]:{sensor['port']}/price"
            price_info = requests.get(price_url, timeout=5).json()
            reading_id_to_buy = price_info['current_reading_id']
            
            confirm = input(f"Purchase latest reading ({reading_id_to_buy}) for {price_info['price_sats']} sats? [y/N]: ")
            if confirm.lower() != 'y':
                logger.info("Purchase cancelled."); sys.exit(0)

            purchased_data = api.purchase_reading(sensor, reading_id_to_buy, consumer_priv_key)
            if purchased_data:
                print("\n--- SINGLE PURCHASE COMPLETE ---")
                print(json.dumps(purchased_data, indent=2))
            else:
                logger.error("Single reading purchase failed. Please check logs for details.")

        except Exception as e:
            logger.error(f"Could not get purchase details from sensor: {e}"); sys.exit(1)

if __name__ == "__main__":
    main()