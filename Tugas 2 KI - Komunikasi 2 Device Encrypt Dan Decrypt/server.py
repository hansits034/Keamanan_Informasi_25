import socket
import threading
from des_implementation import DESImplementation

HOST = '127.0.0.1'  
PORT = 12345
KEY = "mysecret" 

des = DESImplementation()

def handle_client(conn, addr):
    print(f"[KONEKSI] {addr} terhubung.")
    
    def receive_messages():
        while True:
            try:
                data_hex = conn.recv(1024).decode('utf-8')
                if not data_hex:
                    print(f"\n[KONEKSI] {addr} terputus.")
                    break
                
                print(f"\n[PESAN DARI {addr}]")
                print(f"  > Ciphertext: {data_hex}")
                print(f"  > Kunci     : {KEY}")

                decrypted_message = des.decrypt(data_hex, KEY)
                
                print(f"  > Plaintext : '{decrypted_message}'")
                print("[BALAS PESAN] : ")
                
            except Exception as e:
                print(f"[ERROR RECEIVE] {e}")
                break
        conn.close()

    receive_thread = threading.Thread(target=receive_messages, daemon=True)
    receive_thread.start()

    try:
        while True:
            message = input("[KIRIM PESAN]: ")
            if message.lower() == 'exit':
                break
            
            encrypted_hex = des.encrypt(message, KEY)
            
            print(f"   [MEMBALAS KE {addr}]") 
            print(f"   > Plaintext : '{message}'")
            print(f"   > Ciphertext: {encrypted_hex}")
            print(f"   > Kunci     : {KEY}")

            conn.sendall(encrypted_hex.encode('utf-8'))
            
    except (EOFError, KeyboardInterrupt):
        print("\n[INFO] Menutup koneksi...")
    finally:
        conn.close()


def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.bind((HOST, PORT))
    except OSError as e:
        print(f"[ERROR] Gagal binding ke port {PORT}. Mungkin port sudah digunakan?")
        print(f"Error detail: {e}")
        return
        
    server_socket.listen()
    print(f"[SERVER] Mendengarkan di {HOST}:{PORT}...")

    try:
        conn, addr = server_socket.accept()
        handle_client(conn, addr)
    except KeyboardInterrupt:
        print("\n[SERVER] Server dihentikan.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    if len(KEY.encode('utf-8')) != 8:
        print("Error: Kunci harus tepat 8 karakter.")
    else:
        start_server()