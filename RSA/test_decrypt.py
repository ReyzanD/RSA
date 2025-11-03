from steganography import extract_message_from_image
import base64

# Test extraction
try:
    extracted = extract_message_from_image("stego_image.png")
    print("Extracted message:", extracted)
    # Try to decode base64
    decoded = base64.b64decode(extracted)
    print("Base64 decode successful. Decoded bytes length:", len(decoded))
except Exception as e:
    print("Error:", str(e))
