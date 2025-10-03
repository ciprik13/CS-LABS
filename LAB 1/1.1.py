def letter_to_num(letter):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return alphabet.index(letter)

def num_to_letter(num):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return alphabet[num % 26]

def validate_message(message):
    return all(char.isalpha() for char in message)


def caesar_cipher(message, key, mode):
    message = message.upper().replace(' ', '')
    result = ''
    for char in message:
        num = letter_to_num(char)
        if mode == 'encrypt':
            shifted = (num + key) % 26
        else:  # decrypt
            shifted = (num - key) % 26
        result += num_to_letter(shifted)
    return result

def main():
    mode = input("Choose operation (encrypt/decrypt): ").strip().lower()
    if mode not in ['encrypt', 'decrypt']:
        print("Operation must be 'encrypt' or 'decrypt'.")
        return

    try:
        key = int(input("Enter key (1-25): "))
        if not (1 <= key <= 25):
            print("Key must be between 1 and 25.")
            return
    except ValueError:
        print("Key must be an integer between 1 and 25.")
        return

    message = input("Enter message: ").strip()
    if not validate_message(message.replace(' ', '')):
        print("Message must contain only letters A-Z or a-z.")
        return

    result = caesar_cipher(message, key, mode)
    print("Result:", result)

if __name__ == "__main__":
    main()