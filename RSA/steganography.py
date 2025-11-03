from PIL import Image
import base64

# Function to hide a message inside an image using LSB
def hide_message_in_image(image_path, encrypted_message, output_image_path):
    # Convert the message into ASCII-compatible format (Base64)
    message_base64 = base64.b64encode(encrypted_message).decode('ascii')
    message_base64 += '###'  # Add terminator to mark end of message

    img = Image.open(image_path)

    # Convert the message to binary
    message_binary = ''.join(format(byte, '08b') for byte in message_base64.encode('ascii'))
    pixels = img.load()
    data_index = 0

    for i in range(img.size[0]):
        for j in range(img.size[1]):
            r, g, b, a = pixels[i, j]  # Handle RGBA, unpack all channels
            if data_index < len(message_binary):
                r = int(bin(r)[:-1] + message_binary[data_index], 2)  # Modify LSB of red channel
                data_index += 1
            pixels[i, j] = (r, g, b, a)  # Preserve the alpha channel (if any)
    
    img.save(output_image_path)
    print("Message successfully hidden in the image.")

# Function to extract a hidden message from an image using LSB
def extract_message_from_image(image_path):
    img = Image.open(image_path)
    pixels = img.load()
    message_binary = ''
    
    for i in range(img.size[0]):
        for j in range(img.size[1]):
            r, g, b, a = pixels[i, j]
            message_binary += bin(r)[-1]  # Only take the LSB of the red channel
    
    # Convert binary message to text (base64 string)
    message = ''.join(chr(int(message_binary[i:i + 8], 2)) for i in range(0, len(message_binary), 8))
    # Find the terminator and truncate
    terminator_index = message.find('###')
    if terminator_index != -1:
        message = message[:terminator_index]
    return message.strip()  # Return the base64 string (encrypted message)
