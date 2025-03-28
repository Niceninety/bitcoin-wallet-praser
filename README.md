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

> ![screenshot](https://github.com/user-attachments/assets/b0e0ceac-ffe1-4257-adcb-6788f846d4fa)



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
