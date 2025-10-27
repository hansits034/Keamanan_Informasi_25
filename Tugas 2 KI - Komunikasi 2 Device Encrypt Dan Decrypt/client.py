import socket
import threading
from des_implementation import DESImplementation

HOST = '127.0.0.1' 
PORT = 12345
KEY = "mysecret" 

des = DESImplementation()

def receive_messages(client_socket):
    while True:
        try:
            data_hex = client_socket.recv(1024).decode('utf-8')
            if not data_hex:
                print("[KONEKSI] Server terputus.")
                break
            
            print(f"\n[PESAN DARI SERVER]")
            print(f"  > Ciphertext: {data_hex}")
            print(f"  > Kunci     : {KEY}")
            

            decrypted_message = des.decrypt(data_hex, KEY)
            
            print(f"  > Plaintext : '{decrypted_message}'")
            print("[BALAS PESAN] : ")
            
        except Exception as e:
            print(f"[ERROR RECEIVE] {e}")
            break
    client_socket.close()

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client_socket.connect((HOST, PORT))
        print(f"[KONEKSI] Terhubung ke server di {HOST}:{PORT}")
    except ConnectionRefusedError:
        print(f"[ERROR] Gagal terhubung ke server. Pastikan server sudah berjalan.")
        return
    except Exception as e:
        print(f"[ERROR] {e}")
        return

    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,), daemon=True)
    receive_thread.start()

    try:
        while True:
            message = input("[KIRIM PESAN]: ")
            if message.lower() == 'exit':
                break
            
            encrypted_hex = des.encrypt(message, KEY)
            
            print(f"   [MENGIRIM KE SERVER]")
            print(f"   > Plaintext : '{message}'")
            print(f"   > Ciphertext: {encrypted_hex}")
            print(f"   > Kunci     : {KEY}")
            

            client_socket.sendall(encrypted_hex.encode('utf-8'))
            
    except (EOFError, KeyboardInterrupt):
        print("\n[INFO] Menutup koneksi...")
    finally:
        client_socket.close()

if __name__ == "__main__":
    if len(KEY.encode('utf-8')) != 8:
        print("Error: Kunci harus tepat 8 karakter.")
    else:
        start_client()