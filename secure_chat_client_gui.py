# GUI nâng cấp cho Secure Client
# Gửi văn bản và file được mã hóa AES + RSA, giao diện thân thiện hơn

import socket
import base64
import json
import hashlib
import time
import os
from tkinter import *
from tkinter import filedialog, scrolledtext
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

client_key = RSA.generate(2048)
client_pubkey = client_key.publickey()

def pad(msg):
    return msg + b"\x00" * (16 - len(msg) % 16)

def send_message(message, chat_display):
    try:
        log_path = os.path.join(os.getcwd(), "chat_log.txt")
        s = socket.socket()

        # Cơ chế thử kết nối tối đa 5 lần
        for attempt in range(5):
            try:
                s.connect(("localhost", 8888))
                break
            except ConnectionRefusedError:
                if attempt == 4:
                    raise Exception("Không thể kết nối tới server sau nhiều lần thử.")
                time.sleep(0.5)

        server_pubkey = RSA.import_key(s.recv(4096))

        aes_key = get_random_bytes(32)
        metadata = "user1-session123"
        hash_meta = SHA256.new(metadata.encode())
        signature = pkcs1_15.new(client_key).sign(hash_meta)
        enc_key = PKCS1_v1_5.new(server_pubkey).encrypt(aes_key)
        

        package = {
            "metadata": metadata,
            "signature": base64.b64encode(signature).decode(),
            "enc_aes_key": base64.b64encode(enc_key).decode(),
            "sender_pub": base64.b64encode(client_pubkey.export_key()).decode()
        }
        s.send(json.dumps(package).encode())

        iv = get_random_bytes(16)
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        ciphertext = cipher_aes.encrypt(pad(message.encode()))
        hash_value = hashlib.sha256(iv + ciphertext).hexdigest()

        # Tạo chữ ký số cho toàn bộ gói tin (IV + ciphertext + hash)
        signed_data = iv + ciphertext + hash_value.encode()
        signature = pkcs1_15.new(client_key).sign(SHA256.new(signed_data))
        encrypted_package = {
            "iv": base64.b64encode(iv).decode(),
            "cipher": base64.b64encode(ciphertext).decode(),
            "hash": hash_value,
            "signature": base64.b64encode(signature).decode()
        }
        s.send(json.dumps(encrypted_package).encode())
        s.shutdown(socket.SHUT_WR)  # Thông báo đã gửi xong

        resp = s.recv(1024)
        chat_display.insert(END, f"📤 Đã gửi: {message}\n📩 Phản hồi: {resp.decode()}\n")
        chat_display.see(END)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"[CLIENT] Gửi: {message}\n")
        s.close()
    except Exception as e:
        chat_display.insert(END, f"❌ Gửi thất bại: {str(e)}\n")
        chat_display.see(END)

def browse_file(chat_display):
    file_path = filedialog.askopenfilename()
    if file_path:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        send_message(content, chat_display)

def run_gui():
    win = Tk()
    win.title("🧑‍💻 Secure Client")
    win.geometry("650x500")
    win.configure(bg="#f0f0f0")

    Label(win, text="🔐 Giao diện Gửi Tin Nhắn Bảo Mật", font=("Arial", 14, "bold"), bg="#f0f0f0").pack(pady=10)

    chat_display = scrolledtext.ScrolledText(win, width=75, height=20, font=("Consolas", 10))
    chat_display.pack(padx=10, pady=5)

    Label(win, text="Nhập tin nhắn:", bg="#f0f0f0").pack()
    msg_entry = Entry(win, width=60, font=("Arial", 11))
    msg_entry.pack(pady=5)

    button_frame = Frame(win, bg="#f0f0f0")
    button_frame.pack(pady=10)

    Button(button_frame, text="📨 Gửi tin nhắn", width=20,
           command=lambda: send_message(msg_entry.get(), chat_display)).grid(row=0, column=0, padx=10)
    Button(button_frame, text="📁 Gửi file văn bản", width=20,
           command=lambda: browse_file(chat_display)).grid(row=0, column=1, padx=10)

    win.mainloop()

if __name__ == "__main__":
    run_gui()
