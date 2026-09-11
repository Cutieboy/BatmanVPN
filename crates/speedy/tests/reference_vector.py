"""Independent framing vector. Run in a disposable venv with `pip install blake3`."""
import hmac

from blake3 import blake3


def subkey(purpose):
    # One-block HKDF-Expand(PRK, info, 32).
    return hmac.digest(bytes([7]) * 32, b"SP" + bytes([1, 0, purpose, 1]), "sha256")


route = hmac.digest(subkey(0), b"Speedy v1 route\0" + (100).to_bytes(8, "big"), "sha256")[:8]
header = bytes([1, 3, 0, 0]) + (7).to_bytes(8, "big") + (9).to_bytes(8, "big")
body = bytes(range(32))
mask = blake3(route + body[-16:], key=subkey(1)).digest()
frame = route + bytes(a ^ b for a, b in zip(header, mask)) + body
frame += blake3(frame, key=subkey(2)).digest()[:16]
print(frame.hex())
