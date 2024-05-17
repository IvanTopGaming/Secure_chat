import json
import requests
import rsa
from config import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def connect():
	resp = requests.get(server_ip, verify=False)
	public_key = rsa.PublicKey.load_pkcs1(bytes(json.loads(resp.text), "UTF-8"))

	key = get_random_bytes(32)
	cipher = AES.new(key, AES.MODE_EAX)
	nonce = cipher.nonce

	message = key + b"  " + nonce
	crypto = rsa.encrypt(message, public_key)

	requests.post(server_ip, {"secure_pipe": crypto.hex()}, verify=False)

	return cipher
