
import argparse
import logging
import time
from hashlib import sha256
import hmac
import requests
import sys

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Util.strxor import strxor
    from Crypto.Random import get_random_bytes
except ImportError:
    print("pycryptodome library is not installed. Run 'pip install pycryptodome' to install it.")
    sys.exit(1)

POOL_URL = "etc.hiveon.com"
POOL_PORT = 8888

class HiveonMiner:
    def __init__(self, wallet_address, worker_name):
        self._logger = logging.getLogger("hiveon-miner")
        self._wallet_address = wallet_address
        self._worker_name = worker_name
        self._job = None
        self._job_id = None
        self._nonce = None
        self._hash_result = None

    def _subscribe(self, session):
        self._logger.info("Subscribing to Hiveon pool")
        subscribe_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "mining.subscribe",
            "params": ["Miner", "Hiveon-CustomMiner/1.0.0"]
        }
        response = session.post(f"http://{POOL_URL}:{POOL_PORT}/", json=subscribe_request)
        if response.status_code != 200:
            raise Exception(f"Failed to subscribe: {response.text}")
        result = response.json()["result"]
        session.headers["Authorization"] = f"{result[1]}"
        self._logger.info("Authorized")
        return result

    def _get_job(self, session):
        self._logger.debug("Getting job")
        request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "mining.getJob",
            "params": [self._wallet_address, self._worker_name]
        }
        response = session.post(f"http://{POOL_URL}:{POOL_PORT}/", json=request)
        if response.status_code != 200:
            raise Exception(f"Failed to get job: {response.text}")
        result = response.json()["result"]
        self._logger.debug(f"Got job: {result}")
        return result

    def _submit_hash(self, session):
        self._logger.debug("Submitting hash")
        request = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "mining.submit",
            "params": [self._wallet_address, self._job_id, self._nonce, self._hash_result]
        }
        response = session.post(f"http://{POOL_URL}:{POOL_PORT}/", json=request)

        if response.status_code != 200:
            raise Exception(f"Failed to submit hash: {response.text}")
        result = response.json()["result"]
        self._logger.debug(f"Hash submitted: {result}")
        return result

    def start(self):
        self._logger.info("Starting Hiveon miner")
        session = requests.Session()
        key = self._get_key(session)
        self._subscribe(session)
        while True:
        job = self._get_job(session)
        if job != self._job:
        self._job = job
        self._job_id = job[”job_id”]
        self._nonce = 0
        self._hash_result = “”
        self._logger.debug(f”New job: {job}”)
        block_header = bytearray.fromhex(job[”data”])
  target = bytearray.fromhex(job[”target”])
  for i in range(0, 0x100000000, 1):
    self._nonce = i
    nonce_bytes = i.to_bytes(4, byteorder=”little”)
    hash_input = block_header + nonce_bytes
    sha256_hash = sha256(hash_input).digest()
    first_hash = sha256(sha256_hash).digest()
    hash_result = bytearray(first_hash)
    hash_result.reverse()
    if hash_result < target:
      self._hash_result = hash_result.hex()
      self._submit_hash(session)
      break
  time.sleep(0.1)
def _get_key(self, session):
    self._logger.debug("Getting encryption key")
    request = {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "mining.getEncryptionKey",
        "params": []
    }
    response = session.post(f"http://{POOL_URL}:{POOL_PORT}/", json=request)
    if response.status_code != 200:
        raise Exception(f"Failed to get encryption key: {response.text}")
    result = response.json()["result"]
    self._logger.debug(f"Got key: {result}")
    return result
def _encrypt(self, key, data):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(data, 16))
    return iv + ciphertext
def _decrypt(self, key, data):
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), 16)
    return plaintext
def _get_encrypted_share(self, session, share):
    self._logger.debug(f"Encrypting share: {share}")
    key = bytes.fromhex(self._get_key(session))
    share_bytes = bytearray(share.encode("utf-8"))
    nonce_bytes = self._nonce.to_bytes(4, byteorder="big")
    data = nonce_bytes + share_bytes
    encrypted_data = self._encrypt(key, data)
    self._logger.debug(f"Encrypted share: {encrypted_data.hex()}")
    return encrypted_data
def _submit_share(self, session, encrypted_share):
    self._logger.debug("Submitting share")
    request = {
        "jsonrpc": "2.0",
        "id": 6,
        "method": "mining.submitShare",
        "params": [self._wallet_address, self._worker_name, self._job_id, encrypted_share.hex()]
    }
    response = session.post(f"http://{POOL_URL}:{POOL_PORT}/", json=request)
    if response.status_code != 200:
        raise Exception(f"Failed to submit share: {response.text}")
    result = response.json()["result"]
    self._logger.debug(f"Share submitted: {result}")
    return result
def submit(self, share):
    self._logger.debug(f"Submitting share: {share}")
    session = requests.Session()
    self._subscribe(session)
    self._get_job(session)
    block_header = self._job["header"]
    difficulty = self._job["difficulty"]
    target = (2 ** 256) // difficulty
    self._logger.debug(f"Target: {target}")
    while self._hash_result == "":
        message = block_header + self._nonce.to_bytes(32, byteorder="little")
        message_hash = sha256(sha256(message).digest()).digest()
        hash_int = int.from_bytes(message_hash, byteorder="little")
        if hash_int < target:
            self._logger.debug(f"Found valid hash: {message_hash.hex()}")
            hash_bytes = message_hash.to_bytes(32, byteorder="big")
            self._hash_result = hash_bytes.hex()
            self._submit_hash(session)

            self._nonce = 0
            self._hash_result = ""
        else:
            self._nonce += 1

            if self._nonce % 100000 == 0:
                self._logger.debug(f"Nonce: {self._nonce}")
        time.sleep(0.001)
 


