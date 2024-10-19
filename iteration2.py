# Attempt to decrypt using a wordlist of potential keys
def decrypt_with_wordlist(ciphertext, wordlist):
    for key in wordlist:
        try:
            cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
            decrypted_data = cipher.decrypt(ciphertext)
            if b'BM' in decrypted_data[:2]:  # Check for the bitmap file signature ('BM' in the header)
                return key, decrypted_data
        except ValueError:
            continue
    return None, None

# Load the encrypted data
with open("aes.bmp.enc", "rb") as f:
    ciphertext = f.read()

# Sample wordlist (in practice, you would use a larger wordlist)
wordlist = ["ThisIsA16ByteKey", "AnotherSampleKey", "PotentialKey123"]

# Attempt decryption with the wordlist
key, decrypted_data = decrypt_with_wordlist(ciphertext, wordlist)

if key:
    print(f"Decryption succeeded with key: {key}")
    with open("decrypted_output_with_wordlist.bmp", "wb") as f:
        f.write(decrypted_data)
else:
    print("No valid key found in wordlist.")
