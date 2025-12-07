import socket
import threading
import time
from rsa_manual import RSAManual, serialize, deserialize

# Konfigurasi
HOST = '0.0.0.0' 
PORT = 12345

public_key_db = {} 
pka_rsa = RSAManual()
pka_pub, pka_priv = pka_rsa.generate_keypair()

print(f"[PKA SERVER] Started at {HOST}:{PORT}")
print(f"[PKA INFO] Public Key (e, n): {pka_pub}")
print(f"[PKA INFO] Private Key (d, n): {pka_priv}")
print("="*50)

clients = {}

def handle_client(conn, addr):
    print(f"[CONN] {addr} connected.")
    client_id = None # Inisialisasi variabel agar aman di finally block
    
    try:
        raw_data = conn.recv(4096)
        if not raw_data: return
        reg_data = deserialize(raw_data)
        client_id = reg_data['id']
        client_pub_key = reg_data['pub_key']
        
        public_key_db[client_id] = tuple(client_pub_key) 
        clients[client_id] = conn 
        print(f"[REGISTRY] Registered User: {client_id} with Key: {client_pub_key}")
        
        conn.sendall(serialize({"status": "OK", "pka_pub": pka_pub}))

        while True:
            data = conn.recv(4096)
            if not data: break
            
            request = deserialize(data)
            req_type = request.get('type')
            
            if req_type == 'REQUEST_KEY':
                target_id = request['target']
                timestamp = request['time']
                
                print(f"[PKA] Menerima Request dari {client_id} untuk kunci {target_id} | Time: {timestamp}")
                
                target_pub_key = public_key_db.get(target_id)
                
                if target_pub_key:
                    payload_str = f"{target_pub_key}||{req_type}||{timestamp}"
                    signature = pka_rsa.encrypt_string(payload_str, pka_priv)
                    
                    response = {
                        "type": "KEY_RESPONSE",
                        "data": signature 
                    }
                    conn.sendall(serialize(response))
                    print(f"[PKA] Mengirim balasan terenkripsi (Signed) ke {client_id}")
                else:
                    print(f"[PKA] Error: Target {target_id} tidak ditemukan.")

            elif req_type == 'DES_MESSAGE':
                target_id = request['target']
                ciphertext_hex = request['content']
                # [PERBAIKAN DISINI] Ambil signature dari paket pengirim
                signature_data = request.get('signature') 
                
                if target_id in clients:
                    print(f"[RELAY] Meneruskan pesan DES dari {client_id} ke {target_id}")
                    relay_pkg = {
                        "type": "DES_INCOMING",
                        "sender": client_id,
                        "content": ciphertext_hex,
                        "signature": signature_data # [PERBAIKAN] Teruskan signature ke penerima
                    }
                    clients[target_id].sendall(serialize(relay_pkg))
                else:
                    print(f"[RELAY] Gagal mengirim. {target_id} tidak terhubung.")

    except Exception as e:
        print(f"[ERROR] {addr}: {e}")
    finally:
        if client_id and client_id in clients:
            del clients[client_id]
        conn.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    start_server()
