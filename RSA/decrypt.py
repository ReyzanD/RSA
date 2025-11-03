import rsa
import base64
from tkinter import Tk, Label, Button, Text, filedialog
from PIL import Image

# Function to extract the encrypted message (in base64) from the image using LSB
def extract_message_from_image(image_path):
    img = Image.open(image_path)
    pixels = img.load()
    message_binary = ''
    
    # Loop through every pixel to extract LSB from the red channel
    for i in range(img.size[0]):
        for j in range(img.size[1]):
            r, g, b, a = pixels[i, j]  # Handle RGBA, unpack all channels
            message_binary += bin(r)[-1]  # Only take the LSB of the red channel
    
    # Convert binary message to text (this is the base64-encoded encrypted message)
    message = ''.join(chr(int(message_binary[i:i + 8], 2)) for i in range(0, len(message_binary), 8))
    # Find the terminator and truncate
    terminator_index = message.find('###')
    if terminator_index != -1:
        message = message[:terminator_index]
    return message.strip()  # Return the extracted base64 string (the encrypted message)

# Function to decrypt the message using RSA private key
def decrypt_message(encrypted_message, private_key_file):
    with open(private_key_file, 'rb') as priv_file:
        private_key = rsa.PrivateKey.load_pkcs1(priv_file.read())
    decrypted_message = rsa.decrypt(encrypted_message, private_key).decode()
    return decrypted_message

# Function to handle image decryption
def decrypt_from_image():
    # Open a file dialog to choose the image
    image_path = filedialog.askopenfilename(title="Select Stego Image", filetypes=[("PNG Files", "*.png")])
    
    if image_path:
        try:
            # Extract the encrypted message (base64) from the image
            extracted_encrypted_message = extract_message_from_image(image_path)
            
            # Decode the base64 string to get the encrypted bytes
            encrypted_message = base64.b64decode(extracted_encrypted_message)

            # Decrypt the message using the private RSA key
            decrypted_message = decrypt_message(encrypted_message, 'private.pem')

            # Update the GUI with the decrypted message
            decrypted_text_box.delete("1.0", "end-1c")
            decrypted_text_box.insert("1.0", decrypted_message)
            output_label.config(text="Decryption successful!")
        except Exception as e:
            output_label.config(text=f"Error during decryption: {str(e)}")

# GUI Setup
def setup_gui():
    global decrypted_text_box, output_label

    # Create the main window
    root = Tk()
    root.title("Decrypt Hidden Message from Image")

    # Instructions label
    label_instruction = Label(root, text="Click the button to decrypt message from image")
    label_instruction.pack()

    # Output label for status
    output_label = Label(root, text="")
    output_label.pack()

    # Decrypted message text box
    decrypted_text_box = Text(root, height=4, width=50)
    decrypted_text_box.pack()

    # Button to trigger decryption
    decrypt_button = Button(root, text="Decrypt from Image", command=decrypt_from_image)
    decrypt_button.pack()

    # Run the GUI
    root.mainloop()

# Run the program
if __name__ == "__main__":
    setup_gui()
