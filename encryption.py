import rsa

# Function to generate RSA keys (public and private keys)
def generate_keys():
    # Generate RSA keys with a larger key size (1024-bit)
    public_key, private_key = rsa.newkeys(1024)
    with open('public.pem', 'wb') as pub_file:
        pub_file.write(public_key.save_pkcs1('PEM'))
    with open('private.pem', 'wb') as priv_file:
        priv_file.write(private_key.save_pkcs1('PEM'))
    print("RSA keys have been generated and saved with 1024-bit keys.")

# Function to encrypt a message with the public key
def encrypt_message(message, public_key_file):
    with open(public_key_file, 'rb') as pub_file:
        public_key = rsa.PublicKey.load_pkcs1(pub_file.read())
    encrypted_message = rsa.encrypt(message.encode(), public_key)
    return encrypted_message

# Function to decrypt a message with the private key
def decrypt_message(encrypted_message, private_key_file):
    with open(private_key_file, 'rb') as priv_file:
        private_key = rsa.PrivateKey.load_pkcs1(priv_file.read())
    decrypted_message = rsa.decrypt(encrypted_message, private_key).decode()
    return decrypted_message
