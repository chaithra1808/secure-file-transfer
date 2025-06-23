from flask import Flask, render_template, request, redirect, flash
import socket
import os
from utils import encrypt_file, encrypt_key, sha256_hash
from Crypto.Random import get_random_bytes
import tempfile

app = Flask(__name__)
app.secret_key = "supersecretkey"

PORT = 9999

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        # Get form data
        send_file = request.files.get("send_file")
        pub_key_file = request.files.get("pub_key_file")
        receiver_ip = request.form.get("receiver_ip")

        if not send_file or not pub_key_file or not receiver_ip:
            flash("All fields are required.")
            return redirect("/")

        # Save files temporarily
        send_temp_path = tempfile.mktemp()
        pub_key_temp_path = tempfile.mktemp()
        send_file.save(send_temp_path)
        pub_key_file.save(pub_key_temp_path)

        try:
            # Open socket connection
            s = socket.socket()
            s.connect((receiver_ip, PORT))

            filename = send_file.filename
            filename_bytes = filename.encode()

            # Send filename length + filename
            s.send(len(filename_bytes).to_bytes(4, "big"))
            s.send(filename_bytes)

            # Send SHA-256 hash
            file_hash = bytes.fromhex(sha256_hash(send_temp_path))
            s.send(file_hash)

            # Encrypt file and AES key
            aes_key = get_random_bytes(32)
            enc_file = encrypt_file(send_temp_path, aes_key)
            enc_key = encrypt_key(aes_key, pub_key_temp_path)

            # Send AES key length + encrypted key
            s.send(len(enc_key).to_bytes(4, "big"))
            s.send(enc_key)

            # Send encrypted file content
            s.sendall(enc_file)

            s.close()

            flash(f"Sent {filename} successfully!")

        except Exception as e:
            flash(f"Error sending file: {e}")

        finally:
            # Clean up temp files
            if os.path.exists(send_temp_path):
                os.remove(send_temp_path)
            if os.path.exists(pub_key_temp_path):
                os.remove(pub_key_temp_path)

        return redirect("/")

    return render_template("sender.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
