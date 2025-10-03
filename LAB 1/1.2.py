# Caesar cipher implementation with two keys

def letter_to_num(letter):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return alphabet.index(letter)


def num_to_letter(num):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return alphabet[num % 26]


def validate_message(message):
    return all(char.isalpha() for char in message)


def validate_key2(key2):
    if len(key2) < 7:
        return False
    return all(char.isalpha() for char in key2)


def caesar_cipher_with_two_keys(message, key1, key2, mode):
    message = message.upper().replace(' ', '')
    result = ''

    # Convert key2 to uppercase and convert each character to its numeric value
    key2 = key2.upper()
    key2_values = [letter_to_num(char) for char in key2]

    for i, char in enumerate(message):
        num = letter_to_num(char)

        # Get additional shift from key2
        key2_shift = key2_values[i % len(key2)]

        if mode == 'encrypt':
            shifted = (num + key1 + key2_shift) % 26
        else:  # decrypt
            shifted = (num - key1 - key2_shift) % 26

        result += num_to_letter(shifted)

    return result


def main():
    mode = input("Choose operation (encrypt/decrypt): ").strip().lower()
    if mode not in ['encrypt', 'decrypt']:
        print("Operation must be 'encrypt' or 'decrypt'.")
        return

    try:
        key1 = int(input("Enter key1 (1-25): "))
        if not (1 <= key1 <= 25):
            print("Key1 must be between 1 and 25.")
            return
    except ValueError:
        print("Key1 must be an integer between 1 and 25.")
        return

    key2 = input("Enter key2 (at least 7 Latin alphabet letters): ").strip()
    if not validate_key2(key2):
        print("Key2 must contain at least 7 letters from the Latin alphabet (A-Z, a-z).")
        return

    message = input("Enter message: ").strip()
    if not validate_message(message.replace(' ', '')):
        print("Message must contain only letters A-Z or a-z.")
        return

    result = caesar_cipher_with_two_keys(message, key1, key2, mode)
    print("Result:", result)


if __name__ == "__main__":
    main()