# 🧠 Bitcoin Wallet Encrypted Info Extractor

A Python-based tool for extracting encryption metadata from Bitcoin `wallet.dat` files.  
Supports detection of master keys, salt, derivation rounds, address info and wallet left balance using Blockchain API — ready for password recovery workflows like **Hashcat** or **John the Ripper**.

---

## 🔍 Features

- 🧠 Parses `wallet.dat` files from Bitcoin Core
- 🔐 Extracts encrypted master key, salt, and derivation rounds
- 🧾 Generates `$bitcoin$` format hash for cracking
- 📬 Fetches address balance info from blockchain.info
---

## 📸 Screenshot

> ![2025-03-29_03-38-21](https://github.com/user-attachments/assets/16a80e03-1974-4c6e-9535-e46fecd8c1a7)
> The wallet.dat file in the screenshot maybe a fake wallet, which i downloaded from the Internet.




---

## ⚙️ Installation

### 🔧 Requirements

- Python 3.9+
- `bsddb3`
- `requests`
- `PyQt5`
- `packaging`

Install dependencies:

```bash
pip install -r requirements.txt
