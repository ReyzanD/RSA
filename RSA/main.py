import rsa
import base64
import pyperclip  # Import pyperclip to copy to clipboard
from tkinter import Tk, Label, Button, Text
from encryption import encrypt_message, decrypt_message
from steganography import hide_message_in_image, extract_message_from_image

# Declare global variables for the widgets
input_text = None
encrypted_text_box = None
decrypted_text_box = None
output_label = None
encrypt_button = None
decrypt_button = None
encrypt_to_image_button = None
decrypt_from_image_button = None

# Function to encrypt or decrypt based on user input
def encrypt_decrypt():
    message = input_text.get("1.0", "end-1c")  # Get message from text box for encryption or decryption
    
    if encrypt_button["state"] == "normal":
        # Encrypt the message using RSA
        encrypted_message = encrypt_message(message, 'public.pem')
        encrypted_message_base64 = base64.b64encode(encrypted_message).decode()

        # Show encrypted message in the output area
        encrypted_text_box.delete("1.0", "end-1c")  # Clear the box before inserting new content
        encrypted_text_box.insert("1.0", encrypted_message_base64)  # Insert the encrypted message (Base64)

        # Hide the encrypted message inside an image
        hide_message_in_image("input_image.png", encrypted_message, "stego_image.png")
        output_label.config(text="Encrypted message hidden inside 'stego_image.png'.")
    else:
        # Decrypt the message using RSA (after base64 decoding)
        try:
            encrypted_message = base64.b64decode(message)
            decrypted_message = decrypt_message(encrypted_message, 'private.pem')

            decrypted_text_box.delete("1.0", "end-1c")  # Clear decrypted text box before inserting
            decrypted_text_box.insert("1.0", decrypted_message)  # Insert decrypted message

            output_label.config(text=f"Decrypted Message: {decrypted_message}")
        except Exception as e:
            output_label.config(text=f"Error during decryption: {str(e)}")

# Function to decrypt message from an image
def decrypt_from_image():
    # Extract the encrypted message from the image
    extracted_encrypted_message = extract_message_from_image("stego_image.png")

    # Ensure the extracted message is in the correct format for decryption (Base64 decoding if necessary)
    try:
        # If the extracted message is base64-encoded, decode it first to get the original encrypted bytes
        encrypted_message = base64.b64decode(extracted_encrypted_message)

        # Now, decrypt the message using the RSA private key
        decrypted_message = decrypt_message(encrypted_message, 'private.pem')

        # Display the decrypted message
        decrypted_text_box.delete("1.0", "end-1c")  # Clear decrypted text box before inserting
        decrypted_text_box.insert("1.0", decrypted_message)  # Insert decrypted message

        output_label.config(text=f"Decrypted Message from Image: {decrypted_message}")
    except Exception as e:
        # Handle decryption errors and show the error message
        output_label.config(text=f"Error during decryption: {str(e)}")


# GUI setup
def setup_gui():
    global input_text, encrypted_text_box, decrypted_text_box, output_label, encrypt_button, decrypt_button, encrypt_to_image_button, decrypt_from_image_button

    root = Tk()
    root.title("RSA Encryption and Decryption")

    # Instructions
    label_instruction = Label(root, text="Enter Message to Encrypt or Encrypted Text to Decrypt:")
    label_instruction.pack()

    # Text box for input message (either plaintext or encrypted message)
    input_text = Text(root, height=4, width=50)
    input_text.pack()

    # Output label for showing results
    output_label = Label(root, text="")
    output_label.pack()

    # Encrypted message text box to allow copying
    encrypted_text_box = Text(root, height=4, width=50)
    encrypted_text_box.pack()

    # Decrypted message text box
    decrypted_text_box = Text(root, height=4, width=50)
    decrypted_text_box.pack()

    # Encrypt button
    encrypt_button = Button(root, text="Encrypt", command=encrypt_decrypt, state="normal")
    encrypt_button.pack()

    # Decrypt button (disabled by default)
    decrypt_button = Button(root, text="Decrypt", command=encrypt_decrypt, state="disabled")
    decrypt_button.pack()

    # Encrypt to image button
    encrypt_to_image_button = Button(root, text="Encrypt to Image", command=encrypt_decrypt)
    encrypt_to_image_button.pack()

    # Decrypt from image button
    decrypt_from_image_button = Button(root, text="Decrypt from Image", command=decrypt_from_image)
    decrypt_from_image_button.pack()

    # Function to switch between encrypt and decrypt modes
    def toggle_mode():
        if encrypt_button["state"] == "normal":
            encrypt_button["state"] = "disabled"
            decrypt_button["state"] = "normal"
            output_label.config(text="Enter the encrypted text for decryption:")
        else:
            encrypt_button["state"] = "normal"
            decrypt_button["state"] = "disabled"
            output_label.config(text="Enter message to encrypt:")

    # Toggle between encrypt and decrypt modes
    toggle_button = Button(root, text="Switch to Decrypt Mode", command=toggle_mode)
    toggle_button.pack()

    root.mainloop()

# Run the program
if __name__ == "__main__":
    setup_gui()
