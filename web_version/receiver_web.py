from flask import Flask, render_template
import socket
import threading
import os
from utils import decrypt_file, decrypt_key, sha256_hash

PORT = 9999
SAVE_FOLDER = "received_files"
os.makedirs(SAVE_FOLDER, exist_ok=True)

app = Flask(__name__)

received_files = []  # list of dicts: {filename, status}

def receiver_thread(priv_key_path):
    s = socket.socket()
    s.bind(("0.0.0.0", PORT))
    s.listen(1)
    print(f"Receiver listening on port {PORT}")

    while True:
        conn, addr = s.accept()
        print(f"Connected by {addr}")

        try:
            # Receive filename length + filename
            filename_len = int.from_bytes(conn.recv(4), "big")
            filename_bytes = b""
            while len(filename_bytes) < filename_len:
                chunk = conn.recv(filename_len - len(filename_bytes))
                filename_bytes += chunk
            filename = filename_bytes.decode()

            # Receive SHA-256 hash
            expected_hash = b""
            while len(expected_hash) < 32:
                chunk = conn.recv(32 - len(expected_hash))
                expected_hash += chunk

            # Receive AES key length + key
            key_len = int.from_bytes(conn.recv(4), "big")
            enc_key = b""
            while len(enc_key) < key_len:
                chunk = conn.recv(key_len - len(enc_key))
                enc_key += chunk

            aes_key = decrypt_key(enc_key, priv_key_path)

            # Receive encrypted file content
            enc_file = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                enc_file += chunk

            # Decrypt file and save
            data = decrypt_file(enc_file, aes_key)
            save_path = os.path.join(SAVE_FOLDER, filename)
            with open(save_path, "wb") as f:
                f.write(data)

            # Verify hash
            actual_hash = bytes.fromhex(sha256_hash(save_path))
            status = "Verified" if actual_hash == expected_hash else "Corrupted"

            received_files.append({"filename": filename, "status": status})

        except Exception as e:
            received_files.append({"filename": "Unknown", "status": f"Error: {e}"})

        conn.close()

@app.route("/")
def index():
    return render_template("receiver.html", files=received_files)

if __name__ == "__main__":
    priv_key_path = "private.pem"  # Change if needed

    # Start receiver thread
    t = threading.Thread(target=receiver_thread, args=(priv_key_path,), daemon=True)
    t.start()

    app.run(host="0.0.0.0", port=5001)
