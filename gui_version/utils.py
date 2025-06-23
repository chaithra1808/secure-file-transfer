from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

def pad(data):
    return data + b"\0" * (16 - len(data) % 16)

def encrypt_file(file_path, aes_key):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    with open(file_path, 'rb') as f:
        plaintext = pad(f.read())
    ciphertext = cipher.encrypt(plaintext)
    return cipher.iv + ciphertext

def decrypt_file(ciphertext, aes_key):
    iv = ciphertext[:16]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[16:])
    return plaintext.rstrip(b"\0")

def encrypt_key(aes_key, pub_key_path):
    recipient_key = RSA.import_key(open(pub_key_path).read())
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    return cipher_rsa.encrypt(aes_key)

def decrypt_key(enc_key, priv_key_path):
    private_key = RSA.import_key(open(priv_key_path).read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(enc_key)

def sha256_hash(file_path):
    h = SHA256.new()
    with open(file_path, 'rb') as f:
        h.update(f.read())
    return h.hexdigest()
