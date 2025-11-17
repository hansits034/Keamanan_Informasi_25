import socket
import threading
import time
from rsa_manual import RSAManual, serialize, deserialize

# Konfigurasi
HOST = '0.0.0.0' # Bind ke semua interface, IP mesin1/server ini 172.16.16.101
PORT = 12345

# Database Key Publik (Simulasi database PKA)
# A dan B generate key pas runtime, key diterima saat registrasi awal 
# Untuk simulasi, kita anggap mereka mengirim key saat "connect" pertama kali untuk disimpan
public_key_db = {} 

# PKA Keys
pka_rsa = RSAManual()
pka_pub, pka_priv = pka_rsa.generate_keypair()

print(f"[PKA SERVER] Started at {HOST}:{PORT}")
print(f"[PKA INFO] Public Key: {pka_pub}")
print("="*50)

# List koneksi untuk Chat Relay
clients = {}

def handle_client(conn, addr):
    print(f"[CONN] {addr} connected.")
    
    try:
        # Registrasi Awal
        # Client mengirim ID dan Public Key mereka
        raw_data = conn.recv(4096)
        if not raw_data: return
        reg_data = deserialize(raw_data)
        client_id = reg_data['id']
        client_pub_key = reg_data['pub_key']
        
        public_key_db[client_id] = tuple(client_pub_key) 
        clients[client_id] = conn # Simpan koneksi untuk relay chat
        print(f"[REGISTRY] Registered User: {client_id} with Key: {client_pub_key}")
        
        # Kirim Public Key PKA ke client agar mereka bisa verifikasi tanda tangan PKA
        conn.sendall(serialize({"status": "OK", "pka_pub": pka_pub}))

        # Loop
        while True:
            data = conn.recv(4096)
            if not data: break
            
            request = deserialize(data)
            req_type = request.get('type')
            
            # Protocol 1, distribusi public key
            if req_type == 'REQUEST_KEY':
                # Step 1 (A) or 4 (B): menerima request dari client
                target_id = request['target']
                timestamp = request['time']
                
                print(f"[PKA] Menerima Request dari {client_id} untuk kunci {target_id} | Time: {timestamp}")
                
                target_pub_key = public_key_db.get(target_id)
                
                if target_pub_key:
                    # Step 2 or 5: PKA menjawab dengan pesan terenkripsi (PR auth, [PublicKeyTarget || Request || Time])
                    payload_str = f"{target_pub_key}||{req_type}||{timestamp}"
                    
                    # Encrypt menggunakan Private Key PKA (Signing)
                    signature = pka_rsa.encrypt_string(payload_str, pka_priv)
                    
                    response = {
                        "type": "KEY_RESPONSE",
                        "data": signature 
                    }
                    conn.sendall(serialize(response))
                    print(f"[PKA] Mengirim balasan terenkripsi (Signed) ke {client_id}")
                else:
                    print(f"[PKA] Error: Target {target_id} tidak ditemukan.")

            # DES Relay untuk chatting
            elif req_type == 'DES_MESSAGE':
                target_id = request['target']
                ciphertext_hex = request['content']
                
                if target_id in clients:
                    print(f"[RELAY] Meneruskan pesan DES dari {client_id} ke {target_id}")
                    relay_pkg = {
                        "type": "DES_INCOMING",
                        "sender": client_id,
                        "content": ciphertext_hex
                    }
                    clients[target_id].sendall(serialize(relay_pkg))
                else:
                    print(f"[RELAY] Gagal mengirim. {target_id} tidak terhubung.")

    except Exception as e:
        print(f"[ERROR] {addr}: {e}")
    finally:
        if 'client_id' in locals() and client_id in clients:
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
