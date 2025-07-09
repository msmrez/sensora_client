# Sensōra Client - A Consumer & Utility Toolkit

This repository contains `client.py`, a command-line tool for interacting with the **Sensōra Network**. It demonstrates the complete, end-to-end process of discovering, purchasing, and cryptographically verifying data from an autonomous [Sensōra Agent](https://github.com/msmrez/sensora_agent).

This client is designed to work with a running [Sensōra Indexer & Registry](https://github.com/msmrez/sensora_indexer) to find available sensors.

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

## Features

- **Intelligent Discovery:** Automatically queries a Sensōra Indexer to find the most reputable sensor for a desired data type.
- **Single & Batch Purchasing:** Supports buying both the latest single reading and large historical batches of data.
- **On-Chain Payment Tagging:** Creates a `SENSORA_PAY` transaction on the BSV blockchain to reference every purchase.
-   **Full Cryptographic Verification:** After downloading data, the client fetches the original `SENSORA_PROOF` from the blockchain and verifies the data hash, guaranteeing its authenticity.
- **Interactive & User-Friendly:** Presents a clear quote and asks for user confirmation before spending any funds.

## On-Chain Protocol

The client **creates** the `SENSORA_PAY` protocol on the BSV blockchain to reference a purchase.

- **Prefix:** `SENSORA_PAY` (ASCII)
- **Example Payload (Single):** `SENSORA_PAY:1752062495`
- **Example Payload (Batch):** `SENSORA_PAY:a02d33a0db17f45640e354f4a644fa31048ca6babf599af0c17923d65fe93055`
- **Structure:** `[Prefix]:[reading_id or batch_id]`

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
    The client has a `src` directory structure. You must install the dependencies and then install the client itself in editable mode so Python can find the modules.
    ```bash
    pip install -r requirements.txt
    pip install -e . 
    ```

4.  **Configure the Indexer URL:**
    You must tell the client where to find the Sensōra Indexer. Create a configuration file from the example:
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

The client is a flexible command-line tool run via `client.py`.

**To purchase the latest single reading:**
```bash
python client.py "YOUR_WIF_PRIVATE_KEY_HERE"
```

**To purchase a batch of historical data:**
Use the `--start` and `--end` flags with dates in `YYYY-MM-DD` format.
```bash
python client.py "YOUR_WIF_PRIVATE_KEY_HERE" --start "2025-07-01" --end "2025-07-09"
```

**To purchase a different data type:**
Use the `--type` flag.
```bash
python client.py "YOUR_WIF_PRIVATE_KEY_HERE" --type 2
```

The script will find the best sensor, print a quote, ask for your confirmation, and then perform the entire purchase and verification flow, printing detailed logs along the way.
