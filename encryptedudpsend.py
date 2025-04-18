# secure_udp_sender.py
import socket
import time
# from encryptor import generate_key_iv, encrypt_file
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def generate_key_iv():
    key = get_random_bytes(32)  
    iv = get_random_bytes(16)  
    return key, iv

def encrypt_file(file_path, key, iv):
    with open(file_path, "rb") as f:
        plaintext = f.read()
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext

def decrypt_data(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

UDP_IP = "192.168.1.69"  # Target TV IP
UDP_PORT = 4321
FILE_PATH = "test.txt"
INTERVAL = 3  # Seconds between transmissions

def send_encrypted_file():
    # Generate key and IV (in real applications, these must be securely shared with receiver!)
    key, iv = generate_key_iv()
    print(f"[*] Encryption Key: {base64.b64encode(key).decode()}")
    print(f"[*] Initialization Vector (IV): {base64.b64encode(iv).decode()}")

    # Encrypt the file
    ciphertext = encrypt_file(FILE_PATH, key, iv)
    print(f"[+] File encrypted successfully, size: {len(ciphertext)} bytes")

    # Send encrypted data via UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        while True:
            sock.sendto(ciphertext, (UDP_IP, UDP_PORT))
            print(f"[+] Encrypted data sent to {UDP_IP}:{UDP_PORT}")
            time.sleep(INTERVAL)
    except Exception as e:
        print(f"[-] Error occurred: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    print(f"[*] Starting encrypted file transmission of {FILE_PATH}...")
    send_encrypted_file()