import socket
import threading
import time
import random
from rsa_manual import RSAManual, serialize, deserialize
from des_implementation import DESImplementation

# Server
PKA_IP = '127.0.0.1' # Kalau di pake program progjar harus diganti ini dulu 172.16.16.101
PKA_PORT = 12345

MY_ID = "ID-A"
TARGET_ID = "ID-B"

# Client B
MY_LISTEN_PORT = 9002 
PEER_B_IP = '127.0.0.1' # Kalau di pake program progjar harus diganti ini dulu 172.16.16.103
PEER_B_PORT = 9003

# RSA
rsa = RSAManual()
my_pub, my_priv = rsa.generate_keypair()
pka_pub_key = None 
peer_pub_key = None 
des_secret_key = None 

# Socket PKA (Persistent)
pka_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def listen_for_peer():
    """Server socket untuk menerima koneksi langsung dari B"""
    global des_secret_key
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(('0.0.0.0', MY_LISTEN_PORT))
    listener.listen()
    
    while True:
        conn, addr = listener.accept()
        data = conn.recv(8192)
        if not data: continue
        pkg = deserialize(data)
        
        # Protocol 1 Step 6: B -> A (Encrypted PubA [N1 || N2])
        if pkg['type'] == "P1_STEP_6":
            encrypted_data = pkg['data']
            decrypted_str = rsa.decrypt_string(encrypted_data, my_priv)
            print(f"\n[A] Menerima P1_STEP_6 dari B. Decrypted: {decrypted_str}")
            
            # Parsing N1 || N2
            parts = decrypted_str.split("||")
            recv_n1 = parts[0]
            recv_n2 = parts[1]
            
            # Verifikasi N1
            print(f"[A] Verifikasi N1: OK. N2 diterima: {recv_n2}")
            
            # Protocol 1 Step 7: A -> B (Encrypted PubB [N2])
            send_p1_step_7(recv_n2)

        # Protocol 2 Step 2: B -> A (Encrypted PubA [N1 || N2])
        elif pkg['type'] == "P2_STEP_2":
             # Logika mirip P1 Step 6
             encrypted_data = pkg['data']
             decrypted_str = rsa.decrypt_string(encrypted_data, my_priv)
             print(f"\n[A] Menerima P2_STEP_2 dari B. Isi: {decrypted_str}")
             parts = decrypted_str.split("||")
             n2 = parts[1]
             send_p2_step_3(n2)

        # Protocol 2 Step 4: B -> A (Encrypted PubA [N1, SecretKey])
        elif pkg['type'] == "P2_STEP_4":
            encrypted_data = pkg['data']
            decrypted_str = rsa.decrypt_string(encrypted_data, my_priv)
            print(f"\n[A] Menerima P2_STEP_4 dari B (SECRET KEY!). Decrypted: {decrypted_str}")
            
            parts = decrypted_str.split("||")
            # secret_key ada di index 1
            des_secret_key = parts[1]
            print(f"\n[SUKSES] DES Secret Key Established: {des_secret_key}")
            print("="*50)
            
            # Mulai Chatting via Server Relay
            start_des_chat()
            
        conn.close()

def send_p1_step_7(n2):
    # A -> B with Encrypted(PubB, N2)
    msg = f"{n2}"
    ciphertext = rsa.encrypt_string(msg, peer_pub_key)
    
    # Kirim ke B
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((PEER_B_IP, PEER_B_PORT))
        sock.sendall(serialize({"type": "P1_STEP_7", "data": ciphertext}))
        print(f"[A] Mengirim P1_STEP_7 ke B (N2 terenkripsi).")
    except:
        print("[A] Gagal konek ke B untuk Step 7.")
    finally:
        sock.close()
        
    # Lanjut ke Protocol 2 (Distribution of Secret Key)
    time.sleep(1)
    start_protocol_2()

def send_p2_step_3(n2):
    # A -> B (Enc PubB, N2)
    msg = f"{n2}"
    ciphertext = rsa.encrypt_string(msg, peer_pub_key)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((PEER_B_IP, PEER_B_PORT))
    sock.sendall(serialize({"type": "P2_STEP_3", "data": ciphertext}))
    print(f"[A] Mengirim P2_STEP_3 ke B.")
    sock.close()

def start_protocol_2():
    print("\n--- MEMULAI PROTOKOL 2 (Distribusi Secret Key) ---")
    # Step 1: A -> B (Enc PubB, [N1, ID-A])
    n1 = str(random.randint(1000, 9999))
    payload = f"{n1}||{MY_ID}"
    ciphertext = rsa.encrypt_string(payload, peer_pub_key)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((PEER_B_IP, PEER_B_PORT))
    sock.sendall(serialize({"type": "P2_STEP_1", "data": ciphertext}))
    print(f"[A] Mengirim P2_STEP_1 ke B: {payload} (Terenkripsi)")
    sock.close()

def start_des_chat():
    des = DESImplementation()
    
    # Thread untuk menerima pesan chat dari PKA (Relay)
    def receive_chat():
        while True:
            try:
                data = pka_socket.recv(4096)
                if not data: break
                pkg = deserialize(data)
                if pkg.get('type') == 'DES_INCOMING':
                    sender = pkg['sender']
                    cipher_hex = pkg['content']
                    plaintext = des.decrypt(cipher_hex, des_secret_key)
                    print(f"\n[PESAN MASUK dari {sender}]: {plaintext}")
                    print("[REPLY] > ", end="", flush=True)
            except Exception as e:
                # print(e)
                break

    threading.Thread(target=receive_chat, daemon=True).start()
    
    print("\n--- DES CHAT READY (Client 1 -> Server -> Client 2) ---")
    while True:
        msg = input("[A] Kirim Pesan: ")
        if msg == 'exit': break
        
        enc_hex = des.encrypt(msg, des_secret_key)
        packet = {
            "type": "DES_MESSAGE",
            "target": TARGET_ID,
            "content": enc_hex
        }
        pka_socket.sendall(serialize(packet))

def main():
    global pka_pub_key, peer_pub_key
    
    # Start Listener P2P
    threading.Thread(target=listen_for_peer, daemon=True).start()

    # Konek ke PKA
    pka_socket.connect((PKA_IP, PKA_PORT))
    
    # Registrasi Key Awal
    reg_packet = {"id": MY_ID, "pub_key": my_pub}
    pka_socket.sendall(serialize(reg_packet))
    
    # Terima PKA Pub Key
    resp = deserialize(pka_socket.recv(4096))
    pka_pub_key = tuple(resp['pka_pub'])
    print(f"[A] Terhubung PKA. PKA Public Key: {pka_pub_key}")
    
    input("Tekan Enter untuk memulai Protocol 1 (Minta Kunci B)...")
    
    # Start Protocol 1
    # Step 1: A -> PKA (Request || Time1)
    t1 = str(int(time.time()))
    req = {"type": "REQUEST_KEY", "target": TARGET_ID, "time": t1}
    pka_socket.sendall(serialize(req))
    print(f"[A] Protocol 1 Step 1: Request Key B sent.")
    
    # Step 2: Receive from PKA
    resp = deserialize(pka_socket.recv(4096))
    if resp['type'] == "KEY_RESPONSE":
        signed_data = resp['data']
        decrypted_payload = rsa.decrypt_string(signed_data, pka_pub_key)
        print(f"[A] Protocol 1 Step 2: Balasan PKA (Verified): {decrypted_payload}")
        
        # Parse: PublicKeyB || Request || Time1
        parts = decrypted_payload.split("||")
        key_str = parts[0]
        peer_pub_key = eval(key_str)
        print(f"[A] Public Key B didapat: {peer_pub_key}")
        
        # Step 3: A -> B (Encrypted PubB [ID-A || N1])
        n1 = str(random.randint(1000, 9999))
        payload = f"{MY_ID}||{n1}"
        print(f"[A] Protocol 1 Step 3: Mengirim Nonce {n1} ke B...")
        encrypted_payload = rsa.encrypt_string(payload, peer_pub_key)
        
        # Send P2P to B
        sock_b = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock_b.connect((PEER_B_IP, PEER_B_PORT))
            sock_b.sendall(serialize({"type": "P1_STEP_3", "data": encrypted_payload}))
            sock_b.close()
        except ConnectionRefusedError:
            print("[ERROR] B belum online. Jalankan client_b.py dulu.")

    # Wait for Listener
    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
