# Sensōra Client - A Consumer & Utility Toolkit

This repository contains reference tools for interacting with the **Sensōra Network**. The primary tool, `client.py`, is a command-line application that demonstrates the complete, end-to-end process of discovering, purchasing, and verifying data from an autonomous [Sensōra Agent](https://github.com/msmrez/sensora_agent).

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

## The Data Purchase & Verification Flow

The `client.py` script automates the following steps:

1.  **Discovery:** It queries a Sensōra Indexer to find an active sensor that provides the desired data type.
2.  **Get Price:** It contacts the chosen Sensor Agent directly to get the `reading_id` and price for the latest piece of data.
3.  **Payment:** It constructs and broadcasts a BSV micropayment transaction directly to the Agent's specified payment address.
4.  **Claim Data:** It contacts the Agent again, presenting the `txid` of the payment transaction to prove it has paid.
5.  **Fetch Data:** The Agent verifies the payment on-chain and returns a single-use access token. The client uses this token to download the raw sensor data.
6.  **Verification:** The client fetches the original `SENSORA_PROOF` data stamp from the blockchain, hashes the downloaded data, and compares the hashes to cryptographically verify the data's integrity.

## On-Chain Protocol

To perform the final verification step, the client must be able to parse the `SENSORA_PROOF` data stamp protocol.

- **Prefix:** `SENSORA_PROOF` (ASCII)
- **Payload Structure:**

| Field          | Size (Bytes) | Data Type               | Description                   |
| :------------- | :----------- | :---------------------- | :---------------------------- |
| Prefix         | **13**        | ASCII                   | `SENSORA_PROOF`                     |
| Version        | 1            | Unsigned Byte           | Protocol version (`0x01`)     |
| Device ID Type | 1            | Unsigned Byte           | `0x01` for Full IPv6          |
| Device ID      | 16           | Bytes                   | The sensor's IPv6 address     |
| Reading ID     | 8            | Unsigned Long Long (BE) | Unix timestamp of the reading |
| Data Type      | 2            | Unsigned Short (BE)     | Code for this reading's type  |
| Data Hash      | 32           | Bytes                   | SHA-256 hash of the data      |

## Getting Started

### Prerequisites

- Python 3.10+.
- A **funded** BSV wallet WIF (Wallet Import Format) to pay for data and transaction fees.
- The URL of a running [Sensōra Indexer](https://github.com/msmrez/sensora_indexer) instance.

### Installation & Usage

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

4.  **Run the Client:**
    The client is a command-line tool. You provide the Indexer URL, the data type you want to buy, and your wallet's WIF.

    ```bash
    python client.py <INDEXER_URL> <DATA_TYPE_CODE> <YOUR_CONSUMER_WIF>
    ```

    **Example:**
    To buy temperature/humidity data (code `1`) using the public indexer:

    ```bash
    python client.py http://your-indexer-ip:8081 1 "Your_WIF_private_key_goes_here"
    ```

    The script will print detailed logs as it performs each step of the purchase and verification flow. If successful, it will print the fetched sensor data at the end.
