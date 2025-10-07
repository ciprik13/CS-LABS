def create_playfair_matrix(key):
    # Romanian alphabet without J
    alphabet = "AĂÂBCDEFGHIÎKLMNOPQRSȘTȚUVWXYZ"
    
    key = key.upper().replace('J', 'I')
    seen = set()
    processed_key = []
    
    for char in key:
        if char in alphabet and char not in seen:
            seen.add(char)
            processed_key.append(char)
    
    matrix_chars = processed_key.copy()
    for char in alphabet:
        if char not in seen:
            matrix_chars.append(char)
    
    # Fill remaining spaces to make 36 characters (6x6 matrix)
    while len(matrix_chars) < 36:
        matrix_chars.append('*')
    
    # Create 6x6 matrix
    matrix = []
    for i in range(0, 36, 6):
        row = matrix_chars[i:i+6]
        matrix.append(row)
    
    return matrix


def find_position(matrix, char):
    for i, row in enumerate(matrix):
        for j, c in enumerate(row):
            if c == char:
                return i, j
    return None, None


def print_matrix(matrix):
    print("\nPlayfair Matrix:")
    for row in matrix:
        print(' '.join(row))
    print()


def prepare_text(text):
    alphabet = "AĂÂBCDEFGHIÎKLMNOPQRSȘTȚUVWXYZ"
    text = text.upper().replace('J', 'I')
    cleaned = ''.join([c for c in text if c in alphabet])
    return cleaned


def split_into_pairs(text):
    pairs = []
    i = 0
    
    while i < len(text):
        if i == len(text) - 1:
            pairs.append(text[i] + 'X')
            i += 1
        elif text[i] == text[i + 1]:
            pairs.append(text[i] + 'X')
            i += 1
        else:
            pairs.append(text[i] + text[i + 1])
            i += 2
    
    return pairs


def encrypt_pair(matrix, pair):
    char1, char2 = pair[0], pair[1]
    
    row1, col1 = find_position(matrix, char1)
    row2, col2 = find_position(matrix, char2)
    
    if row1 is None or row2 is None:
        return pair
    
    # Same row
    if row1 == row2:
        new_col1 = (col1 + 1) % 6
        new_col2 = (col2 + 1) % 6
        return matrix[row1][new_col1] + matrix[row2][new_col2]
    
    # Same column
    elif col1 == col2:
        new_row1 = (row1 + 1) % 6
        new_row2 = (row2 + 1) % 6
        return matrix[new_row1][col1] + matrix[new_row2][col2]
    
    # Rectangle
    else:
        return matrix[row1][col2] + matrix[row2][col1]


def decrypt_pair(matrix, pair):
    char1, char2 = pair[0], pair[1]
    
    row1, col1 = find_position(matrix, char1)
    row2, col2 = find_position(matrix, char2)
    
    if row1 is None or row2 is None:
        return pair
    
    # Same row
    if row1 == row2:
        new_col1 = (col1 - 1) % 6
        new_col2 = (col2 - 1) % 6
        return matrix[row1][new_col1] + matrix[row2][new_col2]
    
    # Same column
    elif col1 == col2:
        new_row1 = (row1 - 1) % 6
        new_row2 = (row2 - 1) % 6
        return matrix[new_row1][col1] + matrix[new_row2][col2]
    
    # Rectangle
    else:
        return matrix[row1][col2] + matrix[row2][col1]


def encrypt(plaintext, key):
    matrix = create_playfair_matrix(key)
    prepared = prepare_text(plaintext)
    pairs = split_into_pairs(prepared)
    
    print("Prepared text:", prepared)
    print("Pairs:", ' '.join(pairs))
    print_matrix(matrix)
    
    encrypted_pairs = [encrypt_pair(matrix, pair) for pair in pairs]
    ciphertext = ''.join(encrypted_pairs)
    
    return ciphertext


def decrypt(ciphertext, key):
    matrix = create_playfair_matrix(key)
    prepared = prepare_text(ciphertext)
    
    pairs = [prepared[i:i+2] for i in range(0, len(prepared), 2)]
    
    print("Prepared ciphertext:", prepared)
    print("Pairs:", ' '.join(pairs))
    print_matrix(matrix)
    
    decrypted_pairs = [decrypt_pair(matrix, pair) for pair in pairs]
    plaintext = ''.join(decrypted_pairs)
    
    return plaintext


def validate_input(text):
    allowed = "AĂÂBCDEFGHIÎKLMNOPQRSȘTȚUVWXYZaăâbcdefghiîklmnopqrsștțuvwxyz "
    
    for char in text:
        if char not in allowed:
            return False
    return True


def main():
    print("Playfair Cipher - Lab 3")
    print()
    
    print("Choose operation:")
    print("1. Encrypt")
    print("2. Decrypt")
    
    choice = input("\nEnter option (1/2): ").strip()
    
    if choice not in ['1', '2']:
        print("Invalid option!")
        return
    
    while True:
        key = input("\nEnter key (minimum 7 characters): ").strip()
        
        if len(key) < 7:
            print("Key must be at least 7 characters!")
            continue
        
        if not validate_input(key):
            print("Key contains invalid characters!")
            print("Allowed: A-Z, a-z, Ă, Â, Î, Ș, Ț")
            continue
        
        break
    
    if choice == '1':
        while True:
            plaintext = input("\nEnter message to encrypt: ").strip()
            
            if not validate_input(plaintext):
                print("Message contains invalid characters!")
                print("Allowed: A-Z, a-z, Ă, Â, Î, Ș, Ț")
                continue
            
            if not plaintext:
                print("Message cannot be empty!")
                continue
            
            break
        
        print("\n--- ENCRYPTION ---")
        ciphertext = encrypt(plaintext, key)
        
        print("Ciphertext:", ciphertext)
        spaced = ' '.join([ciphertext[i:i+2] for i in range(0, len(ciphertext), 2)])
        print("Ciphertext (spaced):", spaced)
        
    else:
        while True:
            ciphertext = input("\nEnter ciphertext to decrypt: ").strip()
            
            if not validate_input(ciphertext):
                print("Ciphertext contains invalid characters!")
                print("Allowed: A-Z, a-z, Ă, Â, Î, Ș, Ț")
                continue
            
            if not ciphertext:
                print("Ciphertext cannot be empty!")
                continue
            
            break
        
        print("\n--- DECRYPTION ---")
        plaintext = decrypt(ciphertext, key)
        
        print("Decrypted text:", plaintext)
        print("\nNote: Remove 'X' characters and add spaces manually.")


if __name__ == "__main__":
    main()
