from steganography import extract_message_from_image
from encryption import decrypt_message
import base64

# Test full decryption
try:
    extracted = extract_message_from_image("stego_image.png")
    print("Extracted message:", extracted)
    # Decode base64
    encrypted_bytes = base64.b64decode(extracted)
    print("Base64 decode successful.")
    # Decrypt RSA
    decrypted = decrypt_message(encrypted_bytes, 'private.pem')
    print("RSA decryption successful. Decrypted message:", decrypted)
except Exception as e:
    print("Error:", str(e))
