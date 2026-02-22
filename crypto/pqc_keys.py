import oqs
import json
import os

KEY_DIR     = "/home/twi/AEGIS/crypto/keys"
PRIV_PATH   = f"{KEY_DIR}/dilithium3_private.bin"
PUB_PATH    = f"{KEY_DIR}/dilithium3_public.bin"
PUB_HEX     = f"{KEY_DIR}/dilithium3_public.hex"

def generate_keys():
    os.makedirs(KEY_DIR, exist_ok=True)
    with oqs.Signature("Dilithium3") as signer:
        public_key = signer.generate_keypair()
        private_key = signer.export_secret_key()

    with open(PRIV_PATH, "wb") as f:
        f.write(private_key)
    with open(PUB_PATH, "wb") as f:
        f.write(public_key)
    with open(PUB_HEX, "w") as f:
        f.write(public_key.hex())

    print(f"[PQC-KEYS] Dilithium3 keypair generated")
    print(f"[PQC-KEYS] Private key: {PRIV_PATH}")
    print(f"[PQC-KEYS] Public key:  {PUB_PATH}")
    print(f"[PQC-KEYS] Public hex:  {public_key.hex()[:64]}...")

def load_private_key():
    with open(PRIV_PATH, "rb") as f:
        return f.read()

def load_public_key():
    with open(PUB_PATH, "rb") as f:
        return f.read()

def sign_message(message: bytes) -> bytes:
    private_key = load_private_key()
    with oqs.Signature("Dilithium3", secret_key=private_key) as signer:
        return signer.sign(message)

def verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    with oqs.Signature("Dilithium3") as verifier:
        return verifier.verify(message, signature, public_key)

if __name__ == "__main__":
    generate_keys()
    # Test
    msg = b"AEGIS test message"
    sig = sign_message(msg)
    pub = load_public_key()
    valid = verify_signature(msg, sig, pub)
    print(f"[PQC-KEYS] Signature test: {'VALID' if valid else 'INVALID'}")