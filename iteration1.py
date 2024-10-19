from Crypto.Cipher import AES

def decrypt_ecb(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

# Attempt decryption with an example key
with open("aes.bmp.enc", "rb") as f:
    ciphertext = f.read()

# Sample key (this key is not the correct one, just an example)
key = b'ThisIsA16ByteKey'

# Decryption attempt
decrypted_data = decrypt_ecb(ciphertext, key)
with open("decrypted_output.bmp", "wb") as f:
    f.write(decrypted_data)
