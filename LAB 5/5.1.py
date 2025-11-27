from sympy import isprime, nextprime, mod_inverse, gcd
import random

def text_to_decimal(text):
    """Convert text to decimal via hex ASCII representation"""
    # Get hex representation
    hex_values = [format(ord(char), '02X') for char in text]
    hex_string = ''.join(hex_values)
    
    print(f"The initial plaintext message is:")
    print(f'm = "{text}"')
    print(f"\nConverted to ASCII (hexadecimal representation):")
    print(' '.join(hex_values))
    
    # Convert to decimal
    decimal_value = int(hex_string, 16)
    print(f"\nConverted to decimal:")
    print(f"m = {decimal_value}")
    print("\nThis numeric form will be used for RSA encryption.\n")
    
    return decimal_value

def generate_large_prime(bits=512):
    """Generate a large prime number"""
    # Generate random number with specified bits
    random_num = random.getrandbits(bits)
    # Find next prime
    return nextprime(random_num)

def generate_rsa_keys(name, key_size=512):
    """Generate RSA keys based on name"""
    print("="*80)
    print(f"Task 2.1 — RSA Algorithm")
    print("="*80)
    
    print(f"\n{'='*80}")
    print("Key Generation")
    print("="*80)
    
    # Generate two large prime numbers
    print("\nGenerating large prime numbers...")
    random.seed(hash(name))  # Use name as seed for reproducibility
    
    p = generate_large_prime(key_size)
    q = generate_large_prime(key_size)
    
    print(f"\nTwo large prime numbers were generated:")
    print(f"\np = {p}")
    print(f"\nq = {q}")
    
    # Calculate n and φ(n)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    
    print(f"\nThe RSA modulus is:")
    print(f"n = p · q")
    print(f"\nn = {n}")
    
    print(f"\nEuler's totient:")
    print(f"φ(n) = (p − 1)(q − 1)")
    print(f"\nphi = {phi_n}")
    
    # Choose e (public exponent)
    e = 65537
    if gcd(e, phi_n) != 1:
        # Find a suitable e
        for candidate in range(3, phi_n, 2):
            if gcd(candidate, phi_n) == 1:
                e = candidate
                break
    
    print(f"\nThe public exponent is:")
    print(f"e = {e}")
    
    # Calculate d (private exponent)
    d = mod_inverse(e, phi_n)
    
    print(f"\nThe private exponent:")
    print(f"d = e⁻¹ mod φ(n)")
    print(f"\nd = {d}")
    
    return (e, n), (d, n), p, q

def rsa_encrypt(message, public_key):
    """Encrypt a number using RSA"""
    e, n = public_key
    
    print(f"\n{'='*80}")
    print("Encryption")
    print("="*80)
    print(f"\nc = m^e mod n")
    
    ciphertext = pow(message, e, n)
    
    print(f"\nCiphertext:")
    print(f"c = {ciphertext}")
    
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    """Decrypt a number using RSA"""
    d, n = private_key
    
    print(f"\n{'='*80}")
    print("Decryption")
    print("="*80)
    print(f"\nm_dec = c^d mod n")
    
    decrypted = pow(ciphertext, d, n)
    
    print(f"\nm_dec = {decrypted}")
    
    return decrypted

def decimal_to_text(decimal_value):
    """Convert decimal back to text"""
    hex_string = hex(decimal_value)[2:]  # Remove '0x' prefix
    
    # Pad if odd length
    if len(hex_string) % 2:
        hex_string = '0' + hex_string
    
    # Convert hex pairs to characters
    text = ''.join(chr(int(hex_string[i:i+2], 16)) for i in range(0, len(hex_string), 2))
    return text

# Main execution
if __name__ == "__main__":
    name = "Moisenco Ciprian"
    
    print("="*80)
    print("Message Conversion")
    print("="*80)
    print()
    
    # Convert message to decimal
    message = text_to_decimal(name)
    
    # Generate RSA keys
    public_key, private_key, p, q = generate_rsa_keys(name, key_size=512)
    
    # Encrypt
    ciphertext = rsa_encrypt(message, public_key)
    
    # Decrypt
    decrypted = rsa_decrypt(ciphertext, private_key)
    
    # Verify
    print(f"\nThe decrypted message matches the original value: {decrypted == message}")
    
    if decrypted == message:
        decrypted_text = decimal_to_text(decrypted)
        print(f"Decrypted text: \"{decrypted_text}\"")
        print("\n✓ RSA Encryption/Decryption successful!")
    else:
        print("\n✗ RSA Encryption/Decryption failed!")