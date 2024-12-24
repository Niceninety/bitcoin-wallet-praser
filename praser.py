import os
import binascii
import logging
import struct
from bsddb3.db import DB, DBError, DB_BTREE, DB_RDONLY, DB_THREAD

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


class SerializationError(Exception):
    pass


class BCDataStream:
    def __init__(self):
        self.input = None
        self.read_cursor = 0

    def clear(self):
        self.input = None
        self.read_cursor = 0

    def write(self, b):
        if self.input is None:
            self.input = b
        else:
            self.input += b

    def read_bytes(self, length):
        if self.input is None or self.read_cursor + length > len(self.input):
            raise SerializationError("Attempt to read past end of buffer")
        result = self.input[self.read_cursor:self.read_cursor + length]
        self.read_cursor += length
        return result

    def read_string(self):
        length = self.read_compact_size()
        return self.read_bytes(length).decode('ascii')

    def read_uint32(self):
        return self._read_num('<I')

    def read_compact_size(self):
        if self.read_cursor >= len(self.input):
            raise SerializationError("Attempt to read past end of buffer")
        size = self.input[self.read_cursor]
        self.read_cursor += 1
        if size == 253:
            return self._read_num('<H')
        elif size == 254:
            return self._read_num('<I')
        elif size == 255:
            return self._read_num('<Q')
        return size

    def _read_num(self, format):
        s = struct.calcsize(format)
        if self.read_cursor + s > len(self.input):
            raise SerializationError("Attempt to read past end of buffer")
        result, = struct.unpack_from(format, self.input, self.read_cursor)
        self.read_cursor += s
        return result


def open_wallet(walletfile):
    """
    Open and return a handle to the wallet database.
    """
    db = DB()
    try:
        db.open(walletfile, "main", DB_BTREE, DB_RDONLY | DB_THREAD)
    except DBError as e:
        logging.error(f"Error opening wallet: {e}")
        raise RuntimeError("Failed to open wallet file.")
    return db


def parse_wallet(db):
    """
    Parse the wallet database and extract keys and addresses.
    """
    json_db = {}
    addresses = []

    def item_callback(item_type, kds, vds):
        if item_type == "mkey":
            enc_key_len = vds.read_compact_size()
            enc_key = binascii.hexlify(vds.read_bytes(enc_key_len)).decode()
            salt_len = vds.read_compact_size()
            salt = binascii.hexlify(vds.read_bytes(salt_len)).decode()
            nDerivationMethod = vds.read_uint32()
            nDerivationIterations = vds.read_uint32()
            json_db['mkey'] = {
                'encrypted_key': enc_key,
                'salt': salt,
                'nDerivationMethod': nDerivationMethod,
                'nDerivationIterations': nDerivationIterations
            }
        elif item_type == "name":
            address = kds.read_string()
            addresses.append(address)

    kds = BCDataStream()
    vds = BCDataStream()

    for key, value in db.items():
        kds.clear()
        kds.write(key)
        vds.clear()
        vds.write(value)
        try:
            item_type = kds.read_string()
            item_callback(item_type, kds, vds)
        except Exception as e:
            logging.error(f"Error parsing item: {e}")
            continue

    if 'mkey' not in json_db:
        raise RuntimeError("Wallet is not encrypted.")

    json_db['addresses'] = addresses
    return json_db


def parse_wallet_file(wallet_file_path):
    """
    Parse a wallet file and return the results.
    """
    if not os.path.exists(wallet_file_path):
        raise FileNotFoundError(f"File not found: {wallet_file_path}")

    logging.info(f"Parsing wallet file: {wallet_file_path}")

    try:
        db = open_wallet(wallet_file_path)
        wallet_data = parse_wallet(db)
        db.close()

        cry_master_full = wallet_data['mkey']['encrypted_key']
        cry_master = cry_master_full[-64:]
        cry_salt = wallet_data['mkey'].get('salt', '')
        cry_rounds = wallet_data['mkey'].get('nDerivationIterations', 0)

        bitcoin_format = f"$bitcoin${len(cry_master)}${cry_master}${len(cry_salt)}${cry_salt}${cry_rounds}$2$00$2$00"

        logging.info(f"Master Key (Last 64 chars): {cry_master}")
        logging.info(f"Salt: {cry_salt}")
        logging.info(f"Derivation Rounds: {cry_rounds}")
        logging.info(f"Bitcoin Format: {bitcoin_format}")
        logging.info(f"Addresses: {wallet_data.get('addresses', [])}")

        return {
            "bitcoin_format": bitcoin_format,
            "cry_master": cry_master,
            "cry_salt": cry_salt,
            "cry_rounds": cry_rounds,
            "addresses": wallet_data.get("addresses", [])
        }
    except Exception as e:
        logging.error(f"Failed to parse wallet file: {e}")
        raise


if __name__ == "__main__":
    wallet_file = input("Enter the path to your wallet.dat file: ").strip()

    try:
        result = parse_wallet_file(wallet_file)
        print("\n=== Wallet Parsing Results ===")
        print(f"Bitcoin Format: {result['bitcoin_format']}")
        print(f"Master Key (Last 64 chars): {result['cry_master']}")
        print(f"Salt: {result['cry_salt']}")
        print(f"Derivation Rounds: {result['cry_rounds']}")
        print("Addresses:")
        for address in result["addresses"]:
            print(f"  - {address}")
    except Exception as e:
        print(f"Error: {e}")
