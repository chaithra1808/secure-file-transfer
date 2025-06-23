import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import socket
import os
from utils import encrypt_file, encrypt_key, decrypt_file, decrypt_key
from Crypto.Random import get_random_bytes

PORT = 9999

class SecureFileTransferApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure File Transfer")
        self.geometry("500x400")

        self.create_widgets()

    def create_widgets(self):
        # Tabs
        self.tabs = tk.Frame(self)
        self.tabs.pack(pady=10)

        self.send_btn = tk.Button(self.tabs, text="Send File", command=self.show_send_frame)
        self.send_btn.grid(row=0, column=0, padx=5)

        self.recv_btn = tk.Button(self.tabs, text="Receive File", command=self.show_recv_frame)
        self.recv_btn.grid(row=0, column=1, padx=5)

        # Send frame
        self.send_frame = tk.Frame(self)
        self.send_file_path = tk.StringVar()
        self.send_pub_key_path = tk.StringVar()
        self.receiver_ip = tk.StringVar(value="127.0.0.1")

        tk.Label(self.send_frame, text="File to send:").pack()
        tk.Entry(self.send_frame, textvariable=self.send_file_path, width=50).pack()
        tk.Button(self.send_frame, text="Browse", command=self.browse_send_file).pack(pady=5)

        tk.Label(self.send_frame, text="Receiver's Public Key:").pack()
        tk.Entry(self.send_frame, textvariable=self.send_pub_key_path, width=50).pack()
        tk.Button(self.send_frame, text="Browse", command=self.browse_send_pub_key).pack(pady=5)

        tk.Label(self.send_frame, text="Receiver IP Address:").pack()
        tk.Entry(self.send_frame, textvariable=self.receiver_ip, width=50).pack(pady=5)

        self.send_status = tk.Label(self.send_frame, text="")
        self.send_status.pack(pady=5)

        tk.Button(self.send_frame, text="Send", command=self.start_send_thread).pack(pady=10)

        # Receive frame
        self.recv_frame = tk.Frame(self)
        self.recv_priv_key_path = tk.StringVar()

        tk.Label(self.recv_frame, text="Private Key:").pack()
        tk.Entry(self.recv_frame, textvariable=self.recv_priv_key_path, width=50).pack()
        tk.Button(self.recv_frame, text="Browse", command=self.browse_recv_priv_key).pack(pady=5)

        self.recv_status = tk.Label(self.recv_frame, text="Click 'Start Receiver' to wait for incoming files.")
        self.recv_status.pack(pady=10)

        tk.Button(self.recv_frame, text="Start Receiver", command=self.start_receiver_thread).pack()

        # Start with send frame visible
        self.show_send_frame()

    def show_send_frame(self):
        self.recv_frame.pack_forget()
        self.send_frame.pack()

    def show_recv_frame(self):
        self.send_frame.pack_forget()
        self.recv_frame.pack()

    def browse_send_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.send_file_path.set(file_path)

    def browse_send_pub_key(self):
        file_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        if file_path:
            self.send_pub_key_path.set(file_path)

    def browse_recv_priv_key(self):
        file_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        if file_path:
            self.recv_priv_key_path.set(file_path)

    def start_send_thread(self):
        threading.Thread(target=self.send_file, daemon=True).start()

    def send_file(self):
        file_path = self.send_file_path.get()
        pub_key_path = self.send_pub_key_path.get()
        receiver_ip = self.receiver_ip.get()

        if not all([file_path, pub_key_path, receiver_ip]):
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        self.send_status.config(text="Connecting to receiver...")

        try:
            s = socket.socket()
            s.connect((receiver_ip, PORT))

            filename = os.path.basename(file_path)
            filename_bytes = filename.encode()

            # Send filename length and filename
            s.send(len(filename_bytes).to_bytes(4, 'big'))
            s.send(filename_bytes)

            # Compute and send SHA-256 hash
            from utils import sha256_hash
            file_hash = bytes.fromhex(sha256_hash(file_path))
            s.send(file_hash)

            # Encrypt file and key
            aes_key = get_random_bytes(32)
            enc_file = encrypt_file(file_path, aes_key)
            enc_key = encrypt_key(aes_key, pub_key_path)

            # Send AES key length and key
            s.send(len(enc_key).to_bytes(4, 'big'))
            s.send(enc_key)

            # Send encrypted file content
            s.sendall(enc_file)

            self.send_status.config(text=f"Sent: {filename}")

            s.close()

        except Exception as e:
            self.send_status.config(text=f"Error: {e}")

    def start_receiver_thread(self):
        threading.Thread(target=self.receive_file, daemon=True).start()

    def receive_file(self):
        priv_key_path = self.recv_priv_key_path.get()
        if not priv_key_path:
            messagebox.showerror("Error", "Please select your private key file.")
            return

        self.recv_status.config(text="Waiting for sender...")

        try:
            s = socket.socket()
            s.bind(("0.0.0.0", PORT))
            s.listen(1)

            conn, addr = s.accept()
            self.recv_status.config(text=f"Connected: {addr}")

            # Receive filename
            filename_len = int.from_bytes(conn.recv(4), 'big')
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

            # Receive AES key length and key
            key_len = int.from_bytes(conn.recv(4), 'big')
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

            # Decrypt and save file
            data = decrypt_file(enc_file, aes_key)
            with open(filename, 'wb') as f:
                f.write(data)

            # Verify SHA-256 hash
            from utils import sha256_hash
            actual_hash = bytes.fromhex(sha256_hash(filename))
            if actual_hash == expected_hash:
                self.recv_status.config(text=f"Received and verified: {filename}")
            else:
                self.recv_status.config(text=f"Received but hash mismatch! File may be corrupted.")

            conn.close()

        except Exception as e:
            self.recv_status.config(text=f"Error: {e}")

if __name__ == "__main__":
    app = SecureFileTransferApp()
    app.mainloop()
