# Sensōra Client - A Consumer & Utility Toolkit

This repository contains `client.py`, a command-line tool for interacting with the **Sensōra Network**. It demonstrates the complete, end-to-end process of discovering, purchasing, and retrieving data from an autonomous [Sensōra Agent](https://github.com/msmrez/sensora_agent).

This client relies on a running [Sensōra Indexer & Registry](https://github.com/msmrez/sensora_indexer) to find available sensors.

### The Sensōra Ecosystem

The Client is the data-consuming component of the network, completing the P2P transaction cycle.

```
┌─────────────────┐   1. Advertise Service   ┌────────────────┐   4. Discover Agent   ┌──────────────┐
│  Sensōra Agent  │  ─────────────────────>  │                │  <───────────────────  │              │
│                 │                          │ BSV Blockchain │                        │ Sensōra      │
│ on IoT Device   │   2. Stamp Data Proof    │                │   5. Purchase Data     │ Client       │
│                 │  <─────────────────────  │ (Ledger)       │  ───────────────────>  │ (This Project)
└─────────────────┘   3. Listen for Ads      └────────────────┘   6. Verify Proof      └──────────────┘
       ^            <─────────────────────                          ^
       │                                  │                         │
       │ 7. Query for Agents              │ 3a. Index results       │
       │                                  │                         │
       └───────────────────────────────────[ Sensōra Indexer ]───────┘
```

## The Data Purchase Flow

The `client.py` script automates the following steps:

1.  **Discovery:** It queries a Sensōra Indexer to find an active sensor that provides the desired data type.
2.  **Get Price:** It contacts the chosen Sensor Agent directly to get the `reading_id` and price for the latest piece of data.
3.  **Payment:** It constructs and broadcasts a BSV micropayment transaction directly to the Agent's specified payment address. This transaction is tagged with the `SENSORA_PAY` protocol.
4.  **Claim Data:** It contacts the Agent again, presenting the `txid` of the payment transaction to prove it has paid.
5.  **Fetch Data:** The Agent verifies the payment on-chain and returns a single-use access token. The client uses this token to download the raw sensor data.

## On-Chain Protocol

The client **creates** the `SENSORA_PAY` protocol on the BSV blockchain to reference a purchase.

- **Prefix:** `SENSORA_PAY` (ASCII)
- **Example Payload:** `SENSORA_PAY:1678886400`
- **Structure:** `[Prefix]:[Reading_ID]`

## Getting Started

### Prerequisites

- Python 3.10+.
- A **funded** BSV wallet WIF (Wallet Import Format) to pay for data and transaction fees.

### Installation & Configuration

1.  **Clone the Repository:**

    ```bash
    git clone https://github.com/msmrez/sensora_client.git
    cd sensora_client
    ```

2.  **Set up Virtual Environment:**

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install Dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure the Indexer URL:**
    You must tell the client where to find the Sensōra Indexer. Create a configuration file:
    ```bash
    # From the sensora_client project root
    cp src/sensora_client/config.py.example src/sensora_client/config.py
    ```
    Now, **edit `src/sensora_client/config.py`** and set the `REGISTRY_API_URL` to the IP address and port of your running indexer.
    ```python
    # Example config.py
    REGISTRY_API_URL = "http://123.45.67.89:8081"
    ```

### Usage

The client is a command-line tool. You provide your wallet's WIF as the only argument. It will automatically discover a sensor offering Temperature/Humidity data (type `1`) and attempt to purchase the latest reading.

```bash
python -m sensora_client.client <YOUR_CONSUMER_WIF>
```

**Example:**

```bash
python -m sensora_client.client "Your_WIF_private_key_goes_here"
```

The script will print detailed logs as it performs each step of the purchase flow. If successful, it will print the fetched sensor data at the end.

## Future Work

- Implement command-line arguments to allow purchasing different data types.
- **Implement final on-chain data verification** by parsing the `SENSORA_PROOF` transaction and comparing data hashes.
- Add more robust error handling and sensor selection logic.
