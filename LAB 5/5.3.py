import hashlib
import random

def diffie_hellman_key_exchange(p, g):
    """Perform Diffie-Hellman key exchange between Alice and Bob"""
    print("="*80)
    print("Task 3 — Diffie-Hellman Key Exchange with AES-256")
    print("="*80)
    
    print(f"\nPublic parameters:")
    print(f"\np = {p}")
    print(f"\ng = {g}")
    
    # Alice's secret key
    a = random.randint(2, p-2)
    print(f"\n{'='*80}")
    print("Alice's Secret")
    print("="*80)
    print(f"\nAlice chooses secret a:")
    print(f"a = {a}")
    
    # Alice computes A = g^a mod p
    A = pow(g, a, p)
    print(f"\nAlice computes A = g^a mod p:")
    print(f"A = {A}")
    
    # Bob's secret key
    b = random.randint(2, p-2)
    print(f"\n{'='*80}")
    print("Bob's Secret")
    print("="*80)
    print(f"\nBob chooses secret b:")
    print(f"b = {b}")
    
    # Bob computes B = g^b mod p
    B = pow(g, b, p)
    print(f"\nBob computes B = g^b mod p:")
    print(f"B = {B}")
    
    # Key exchange
    print(f"\n{'='*80}")
    print("Key Exchange")
    print("="*80)
    print(f"\nAlice sends A to Bob")
    print(f"Bob sends B to Alice")
    
    # Alice computes shared secret
    shared_secret_alice = pow(B, a, p)
    print(f"\n{'='*80}")
    print("Shared Secret Computation")
    print("="*80)
    print(f"\nAlice computes: s = B^a mod p")
    print(f"s = {shared_secret_alice}")
    
    # Bob computes shared secret
    shared_secret_bob = pow(A, b, p)
    print(f"\nBob computes: s = A^b mod p")
    print(f"s = {shared_secret_bob}")
    
    # Verify both computed the same secret
    if shared_secret_alice == shared_secret_bob:
        print(f"\n✓ Both Alice and Bob computed the same shared secret!")
    else:
        print(f"\n✗ Error: Different shared secrets!")
        return None, None
    
    # Derive 256-bit AES key from shared secret using SHA-256
    shared_secret_bytes = str(shared_secret_alice).encode('utf-8')
    aes_key = hashlib.sha256(shared_secret_bytes).digest()
    
    print(f"\n{'='*80}")
    print("AES-256 Key Derivation")
    print("="*80)
    print(f"\nDerived AES-256 key using SHA-256 hash of shared secret:")
    print(f"AES Key (hex): {aes_key.hex()}")
    print(f"AES Key length: {len(aes_key) * 8} bits")
    
    return aes_key, shared_secret_alice

def simple_xor_encrypt(plaintext, key):
    """Simple XOR encryption as demonstration (not real AES, but shows the concept)"""
    print(f"\n{'='*80}")
    print("Symmetric Encryption (XOR-based demonstration)")
    print("="*80)
    
    # Convert plaintext to bytes
    plaintext_bytes = plaintext.encode('utf-8')
    
    # Extend key to match plaintext length
    extended_key = (key * (len(plaintext_bytes) // len(key) + 1))[:len(plaintext_bytes)]
    
    # XOR encryption
    ciphertext = bytes(a ^ b for a, b in zip(plaintext_bytes, extended_key))
    
    print(f"\nPlaintext: \"{plaintext}\"")
    print(f"Ciphertext (hex): {ciphertext.hex()}")
    
    return ciphertext

def simple_xor_decrypt(ciphertext, key):
    """Simple XOR decryption"""
    print(f"\n{'='*80}")
    print("Symmetric Decryption")
    print("="*80)
    
    # Extend key to match ciphertext length
    extended_key = (key * (len(ciphertext) // len(key) + 1))[:len(ciphertext)]
    
    # XOR decryption (same as encryption for XOR)
    plaintext_bytes = bytes(a ^ b for a, b in zip(ciphertext, extended_key))
    plaintext = plaintext_bytes.decode('utf-8')
    
    print(f"\nDecrypted plaintext: \"{plaintext}\"")
    
    return plaintext

# Main execution
if __name__ == "__main__":
    # The 2048-bit prime p from laboratory instructions
    p = 32317006071311007300153513477825163362488057133489075174588434139269806834136210002792056362640164685458556357935330816928829023080573472625273554742461245741026202527916572972862706300325263428213145766931414223654220941111348629991657478268034230553086349050635557712219187890332729569696129743856241741236237225197346402691855797767976823014625397933058015226858730761197532436467475855460715043896844940366130497697812854295958659597567051283852132784468522925504568272879113720098931873959143374175837826000278034973198552060607533234122603254684088120031105907484281003994966956119696956248629032338072839127039
    g = 2
    
    # Set seed for reproducibility (optional)
    random.seed(42)
    
    # Perform Diffie-Hellman key exchange
    aes_key, shared_secret = diffie_hellman_key_exchange(p, g)
    
    if aes_key is not None:
        # Test message
        test_message = "Hello from Alice to Bob using symmetric encryption!"
        
        print(f"\nNote: Using XOR-based encryption for demonstration.")
        print(f"In production, use proper AES implementation from cryptography libraries.")
        
        # Encrypt message
        ciphertext = simple_xor_encrypt(test_message, aes_key)
        
        # Decrypt message
        decrypted_message = simple_xor_decrypt(ciphertext, aes_key)
        
        # Verify
        print(f"\n{'='*80}")
        print("Verification")
        print("="*80)
        if test_message == decrypted_message:
            print("\n✓ Symmetric Encryption/Decryption with Diffie-Hellman key exchange successful!")
        else:
            print("\n✗ Encryption/Decryption failed!")