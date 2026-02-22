import oqs
import json
import hashlib
from datetime import datetime

def demo_kyber_handshake(client_id, server_id):
    print(f"\n[AEGIS-CRYPTO] Initiating post-quantum key exchange...")
    print(f"[AEGIS-CRYPTO] Algorithm: CRYSTALS-Kyber (NIST PQC Standard 2024)")
    print(f"[AEGIS-CRYPTO] Client: {client_id} → Server: {server_id}")

    # Server generates keypair
    kem = oqs.KeyEncapsulation("Kyber768")
    public_key = kem.generate_keypair()

    # Client encapsulates shared secret using server's public key
    kem_client = oqs.KeyEncapsulation("Kyber768")
    ciphertext, client_shared_secret = kem_client.encap_secret(public_key)

    # Server decapsulates to get same shared secret
    server_shared_secret = kem.decap_secret(ciphertext)

    # Verify both sides have identical secret
    match = client_shared_secret == server_shared_secret

    session_key = hashlib.sha256(client_shared_secret).hexdigest()

    print(f"[AEGIS-CRYPTO] Key exchange: {'SUCCESS' if match else 'FAILED'}")
    print(f"[AEGIS-CRYPTO] Session key: {session_key[:32]}...")
    print(f"[AEGIS-CRYPTO] Key size: {len(client_shared_secret)*8} bits")

    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "algorithm": "Kyber768",
        "client": client_id,
        "server": server_id,
        "session_key": session_key,
        "status": "ESTABLISHED" if match else "FAILED"
    }

def demo_dilithium_signing(message, signer_id):
    print(f"\n[AEGIS-CRYPTO] Signing policy with CRYSTALS-Dilithium...")
    print(f"[AEGIS-CRYPTO] Signer: {signer_id}")

    signer = oqs.Signature("Dilithium3")
    public_key = signer.generate_keypair()

    msg_bytes = message.encode()
    signature = signer.sign(msg_bytes)

    # Verify
    verifier = oqs.Signature("Dilithium3")
    valid = verifier.verify(msg_bytes, signature, public_key)

    print(f"[AEGIS-CRYPTO] Signature: {signature.hex()[:32]}...")
    print(f"[AEGIS-CRYPTO] Verification: {'VALID' if valid else 'INVALID'}")

    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "algorithm": "Dilithium3",
        "signer": signer_id,
        "message": message,
        "signature": signature.hex()[:64],
        "valid": valid
    }

if __name__ == "__main__":
    print("=" * 60)
    print("AEGIS POST-QUANTUM CRYPTOGRAPHY LAYER")
    print("NIST PQC Standards: Kyber768 + Dilithium3")
    print("=" * 60)

    # Simulate secure channel between IDS and Policy Engine
    session = demo_kyber_handshake("IDS-Engine", "Policy-Engine")
    print(f"\n[AEGIS-CRYPTO] Session established: {session['session_key'][:16]}...")

    # Sign a policy mutation
    result = demo_dilithium_signing(
        "BLOCK 10.0.1.1 - POL-001 - ICMP FLOOD",
        "AEGIS-PolicyEngine"
    )
    print(f"\n[AEGIS-CRYPTO] Policy signature valid: {result['valid']}")
    print("\n[AEGIS-CRYPTO] Post-quantum layer operational!")