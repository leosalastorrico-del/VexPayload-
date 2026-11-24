import sys
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP
from Crypto.Hash import SHA256

if len(sys.argv) != 3:
    print("usage: python unwrap.py <priv.pem> <wrapped_key_base64>")
    sys.exit(1)

with open(sys.argv[1], "rb") as f:
    private_key = RSA.import_key(f.read())

wrapped_key = base64.b64decode(sys.argv[2])
aes_key = None
try:
    aes_key = PKCS1_OAEP.new(private_key, hashAlgo=SHA256).decrypt(wrapped_key)
except Exception:
    aes_key = None
if aes_key is None:
    # Legacy payloads used PKCS#1 v1.5; keep the fallback explicit.
    aes_key = PKCS1_v1_5.new(private_key).decrypt(wrapped_key, None)

if aes_key is None:
    print("[-] decryption failed. wrong private key or corrupted payload.")
    sys.exit(1)

print("[+] raw aes key (base64):")
print(base64.b64encode(aes_key).decode())
