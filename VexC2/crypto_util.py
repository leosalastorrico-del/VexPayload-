"""Key handling and container decryption for proof-of-key."""

import base64
import struct

try:
    from Crypto.Cipher import AES, PKCS1_v1_5, PKCS1_OAEP
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
    HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    HAVE_CRYPTO = False

MAX_CONTAINER = 512 * 1024 * 1024   # refuse to expand anything bigger
MAX_CHUNK = 1024 * 1024
MAX_CHUNKS = 2_000_000


def load_private_key(path):
    """Return the RSA private key at path, or None."""
    if not HAVE_CRYPTO:
        return None
    try:
        with open(path, "rb") as f:
            return RSA.import_key(f.read())
    except Exception:
        return None


def unwrap_key(key, wrapped_b64):
    """Return base64(32-byte AES key) or ''. OAEP first; legacy v1.5 fallback."""
    if not key or not wrapped_b64:
        return ""
    try:
        blob = base64.b64decode(wrapped_b64)
    except Exception:
        return ""
    raw = None
    try:
        raw = PKCS1_OAEP.new(key, hashAlgo=SHA256).decrypt(blob)
    except Exception:
        raw = None
    if raw is None or len(raw) != 32:
        try:
            raw = PKCS1_v1_5.new(key).decrypt(blob, None)
        except Exception:
            raw = None
    if raw is None or len(raw) != 32:
        return ""
    return base64.b64encode(raw).decode()


def b64_key(victim_aes_b64):
    try:
        raw = base64.b64decode(victim_aes_b64 or "")
        return raw if len(raw) == 32 else None
    except Exception:
        return None


def decrypt_container(blob: bytes, key: bytes, max_out: int = MAX_CONTAINER) -> bytes:
    """Decrypt a container (VEX2 or legacy v1). Raises ValueError."""
    if len(key) != 32:
        raise ValueError("bad key length")
    if len(blob) < 8:
        raise ValueError("not a container")
    max_out = max(1, min(int(max_out), MAX_CONTAINER))

    if blob[:4] == b"VEX2":
        return _decrypt_v2(blob, key, max_out)

    chunks = struct.unpack("<Q", blob[:8])[0]
    if chunks > MAX_CHUNKS:
        raise ValueError("chunk count out of bounds")
    out = bytearray()
    off = 8
    for _ in range(chunks):
        if off + 12 + 4 > len(blob):
            raise ValueError("truncated chunk header")
        nonce = blob[off:off + 12]
        ln = struct.unpack("<I", blob[off + 12:off + 16])[0]
        off += 16
        if ln == 0 or ln > MAX_CHUNK or off + ln + 16 > len(blob):
            raise ValueError("bad chunk length")
        ct = blob[off:off + ln]
        tag = blob[off + ln:off + ln + 16]
        off += ln + 16
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        out += cipher.decrypt_and_verify(ct, tag)
        if len(out) > max_out:
            raise ValueError("output too large")
    return bytes(out)


def _decrypt_v2(blob: bytes, key: bytes, max_out: int = MAX_CONTAINER) -> bytes:
    if len(blob) < 32:
        raise ValueError("truncated header")
    magic, flags, original, stride, chunk_size, chunks = struct.unpack("<4sIQIIQ", blob[:32])
    if magic != b"VEX2":
        raise ValueError("bad magic")
    if chunk_size < 1024 or chunk_size > MAX_CHUNK:
        raise ValueError("bad chunk size")
    if chunks > MAX_CHUNKS or original > max_out:
        raise ValueError("header out of bounds")

    out = bytearray()
    off = 32
    for _ in range(chunks):
        if off + 5 > len(blob):
            raise ValueError("truncated chunk header")
        mode = blob[off]
        ln = struct.unpack("<I", blob[off + 1:off + 5])[0]
        off += 5
        if ln > chunk_size:
            raise ValueError("bad chunk length")

        if mode == 0:
            if off + ln > len(blob):
                raise ValueError("truncated raw chunk")
            out += blob[off:off + ln]
            off += ln
            continue

        if off + 12 + ln + 16 > len(blob):
            raise ValueError("truncated encrypted chunk")
        nonce = blob[off:off + 12]
        ct = blob[off + 12:off + 12 + ln]
        tag = blob[off + 12 + ln:off + 12 + ln + 16]
        off += 12 + ln + 16
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        out += cipher.decrypt_and_verify(ct, tag)
        if len(out) > max_out:
            raise ValueError("output too large")

    if len(out) != original:
        raise ValueError("size mismatch")
    return bytes(out)


def is_container(blob: bytes) -> bool:
    return blob[:4] == b"VEX2" or (len(blob) >= 8 and
                                   struct.unpack("<Q", blob[:8])[0] <= MAX_CHUNKS)
