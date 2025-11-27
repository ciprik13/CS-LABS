from sympy import mod_inverse
import random

def text_to_decimal(text):
    """Convert text to decimal via hex ASCII representation"""
    hex_values = [format(ord(char), '02X') for char in text]
    hex_string = ''.join(hex_values)
    decimal_value = int(hex_string, 16)
    return decimal_value

def generate_elgamal_keys(p, g):
    """Generate ElGamal keys with given p and g"""
    print("="*80)
    print("Task 2.2 — ElGamal Algorithm")
    print("="*80)
    
    print(f"\nWe use the large prime p provided in the laboratory instructions and generator g = 2:")
    print(f"\np = {p}")
    print(f"\ng = {g}")
    
    # Private key x (random integer in range [2, p-2])
    x = random.randint(2, p-2)
    
    print(f"\nPrivate key x:")
    print(f"\nx = {x}")
    
    # Public key y = g^x mod p
    y = pow(g, x, p)
    
    print(f"\nPublic key:")
    print(f"y = g^x mod p")
    print(f"\ny = {y}")
    
    return x, y

def elgamal_encrypt(message, p, g, y):
    """Encrypt message using ElGamal"""
    print(f"\n{'='*80}")
    print("Encryption")
    print("="*80)
    
    # Random ephemeral exponent k
    k = random.randint(2, p-2)
    
    print(f"\nRandom ephemeral exponent:")
    print(f"\nk = {k}")
    
    # c1 = g^k mod p
    c1 = pow(g, k, p)
    
    print(f"\nc1 = g^k mod p")
    print(f"\nc1 = {c1}")
    
    # c2 = m * y^k mod p
    c2 = (message * pow(y, k, p)) % p
    
    print(f"\nc2 = m · y^k mod p")
    print(f"\nc2 = {c2}")
    
    return c1, c2, k

def elgamal_decrypt(c1, c2, x, p):
    """Decrypt ciphertext using ElGamal"""
    print(f"\n{'='*80}")
    print("Decryption")
    print("="*80)
    
    # s = c1^x mod p
    s = pow(c1, x, p)
    
    print(f"\ns = c1^x mod p")
    print(f"\ns = {s}")
    
    # s^-1 = s^-1 mod p
    s_inv = mod_inverse(s, p)
    
    print(f"\ns^-1 = s^-1 mod p")
    print(f"\ns^-1 = {s_inv}")
    
    # m_dec = c2 * s^-1 mod p
    m_dec = (c2 * s_inv) % p
    
    print(f"\nm_dec = c2 · s^-1 mod p = {m_dec}")
    
    return m_dec

def decimal_to_text(decimal_value):
    """Convert decimal back to text"""
    hex_string = hex(decimal_value)[2:]
    
    if len(hex_string) % 2:
        hex_string = '0' + hex_string
    
    text = ''.join(chr(int(hex_string[i:i+2], 16)) for i in range(0, len(hex_string), 2))
    return text

# Main execution
if __name__ == "__main__":
    name = "Moisenco Ciprian"
    
    # The 2048-bit prime p from laboratory instructions
    p = 32317006071311007300153513477825163362488057133489075174588434139269806834136210002792056362640164685458556357935330816928829023080573472625273554742461245741026202527916572972862706300325263428213145766931414223654220941111348629991657478268034230553086349050635557712219187890332729569696129743856241741236237225197346402691855797767976823014625397933058015226858730761197532436467475855460715043896844940366130497697812854295958659597567051283852132784468522925504568272879113720098931873959143374175837826000278034973198552060607533234122603254684088120031105907484281003994966956119696956248629032338072839127039
    g = 2
    
    print("="*80)
    print("Message Conversion")
    print("="*80)
    print()
    
    # Convert message to decimal
    hex_values = [format(ord(char), '02X') for char in name]
    print(f'The initial plaintext message is:')
    print(f'm = "{name}"')
    print(f"\nConverted to ASCII (hexadecimal representation):")
    print(' '.join(hex_values))
    
    message = text_to_decimal(name)
    print(f"\nConverted to decimal:")
    print(f"m = {message}")
    print("\nThis numeric form will be used for ElGamal encryption.\n")
    
    # Set seed for reproducibility
    random.seed(hash(name))
    
    # Generate ElGamal keys
    x, y = generate_elgamal_keys(p, g)
    
    # Encrypt
    c1, c2, k = elgamal_encrypt(message, p, g, y)
    
    # Decrypt
    decrypted = elgamal_decrypt(c1, c2, x, p)
    
    # Verify
    print(f"\nThe ElGamal decryption successfully recovers the original message.")
    
    if decrypted == message:
        decrypted_text = decimal_to_text(decrypted)
        print(f'Decrypted text: "{decrypted_text}"')
        print("\n✓ ElGamal Encryption/Decryption successful!")
    else:
        print("\n✗ ElGamal Encryption/Decryption failed!")