import socket
import base64
import hashlib
import json
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from tkinter import *
from tkinter import scrolledtext

server_key = RSA.generate(2048)
server_public_key = server_key.publickey()

def handle_client(conn, chat_display):
    try:
        conn.send(server_public_key.export_key())
        package = json.loads(conn.recv(4096).decode())

        enc_aes_key = base64.b64decode(package["enc_aes_key"])
        signature_meta = base64.b64decode(package["signature"])
        metadata = package["metadata"].encode()
        sender_pub = RSA.import_key(base64.b64decode(package["sender_pub"]))

        aes_key = PKCS1_v1_5.new(server_key).decrypt(enc_aes_key, None)
        hash_obj = SHA256.new(metadata)
        pkcs1_15.new(sender_pub).verify(hash_obj, signature_meta)

        encrypted_package_data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            encrypted_package_data += chunk

        encrypted_package = json.loads(encrypted_package_data.decode())

        iv = base64.b64decode(encrypted_package["iv"])
        ciphertext = base64.b64decode(encrypted_package["cipher"])
        received_hash = encrypted_package["hash"]
        signature_final = base64.b64decode(encrypted_package["signature"])

        if hashlib.sha256(iv + ciphertext).hexdigest() != received_hash:
            chat_display.insert(END, "❌ Hash không khớp. Gửi NACK\n")
            chat_display.see(END)
            conn.send(b"NACK")
            return

        signed_data = iv + ciphertext + received_hash.encode()
        hash_obj_final = SHA256.new(signed_data)
        pkcs1_15.new(sender_pub).verify(hash_obj_final, signature_final)

        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        plaintext = cipher_aes.decrypt(ciphertext).rstrip(b"\x00")
        message = plaintext.decode(errors="ignore")

        chat_display.insert(END, f"💬 Nhận: {message}\n")
        chat_display.see(END)
        with open("chat_log.txt", "a", encoding="utf-8") as f:
            f.write(f"[SERVER] Nhận: {message}\n")

        conn.send(b"ACK")

    except (ValueError, KeyError):
        chat_display.insert(END, "❌ Xác thực thất bại hoặc dữ liệu lỗi. Gửi NACK\n")
        chat_display.see(END)
        try:
            conn.send(b"NACK")
        except:
            pass
    except Exception as e:
        chat_display.insert(END, f"❌ Lỗi: {str(e)}\n")
        chat_display.see(END)
        try:
            conn.send(b"NACK")
        except:
            pass
    finally:
        conn.close()

def start_server(chat_display):
    try:
        server_socket = socket.socket()
        server_socket.bind(("localhost", 8888))
        server_socket.listen(5)
        chat_display.insert(END, "🟢 Server đã sẵn sàng tại localhost:8888...\n")
        chat_display.see(END)
        print("🟢 Server đã sẵn sàng...")

        while True:
            conn, addr = server_socket.accept()
            chat_display.insert(END, f"🔌 Đã kết nối từ {addr}\n")
            chat_display.see(END)
            threading.Thread(target=handle_client, args=(conn, chat_display), daemon=True).start()
    except Exception as e:
        chat_display.insert(END, f"❌ Lỗi server: {e}\n")
        chat_display.see(END)

def run_gui():
    win = Tk()
    win.title("🖥️ Secure Server")
    win.geometry("650x500")
    win.configure(bg="#f9f9f9")

    Label(win, text="💾 Server Nhận Tin Nhắn Bảo Mật", font=("Arial", 14, "bold"), bg="#f9f9f9").pack(pady=10)

    chat_display = scrolledtext.ScrolledText(win, width=75, height=25, font=("Consolas", 10))
    chat_display.pack(padx=10, pady=10)

    threading.Thread(target=start_server, args=(chat_display,), daemon=True).start()
    win.mainloop()

if __name__ == "__main__":
    run_gui()
