import socket
import threading
import time
import random
from rsa_manual import RSAManual, serialize, deserialize
from des_implementation import DESImplementation

# Server PKA
PKA_IP = '172.16.16.101' 
PKA_PORT = 12345

# Identitas Diri
MY_ID = "ID-A"
MY_LISTEN_PORT = 9002 

# Identitas & IP Target (Client B)
TARGET_ID = "ID-B"
PEER_B_IP = '172.16.16.103' 
PEER_B_PORT = 9003


# Setup RSA
rsa = RSAManual()
print("\n" + "="*60)
print(f" GENERATING RSA KEYS FOR {MY_ID}...")
my_pub, my_priv = rsa.generate_keypair()
# [TRANSPARANSI RSA]
print(f" [RSA INFO] Public Key (e, n)  : {my_pub}")
print(f" [RSA INFO] Private Key (d, n) : {my_priv}")
print(f" [RSA MATH] e={my_pub[0]}, d={my_priv[0]}, n={my_pub[1]}")
print("="*60 + "\n")

pka_pub_key = None 
peer_pub_key = None 
des_secret_key = None 

# Socket ke PKA (Persistent)
pka_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def listen_for_peer():
    """Server socket untuk menerima koneksi P2P langsung dari B"""
    global des_secret_key
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(('0.0.0.0', MY_LISTEN_PORT))
    listener.listen()
    
    while True:
        conn, addr = listener.accept()
        data = conn.recv(8192)
        if not data: continue
        pkg = deserialize(data)
        
        # Protocol 1 Step 6
        if pkg['type'] == "P1_STEP_6":
            encrypted_data = pkg['data']
            decrypted_str = rsa.decrypt_string(encrypted_data, my_priv)
            print(f"\n[A] Menerima P1_STEP_6 dari B. Decrypted: {decrypted_str}")
            parts = decrypted_str.split("||")
            recv_n2 = parts[1]
            send_p1_step_7(recv_n2)

        # Protocol 2 Step 2
        elif pkg['type'] == "P2_STEP_2":
             encrypted_data = pkg['data']
             decrypted_str = rsa.decrypt_string(encrypted_data, my_priv)
             print(f"\n[A] Menerima P2_STEP_2 dari B. Isi: {decrypted_str}")
             parts = decrypted_str.split("||")
             n2 = parts[1]
             send_p2_step_3(n2)

        # Protocol 2 Step 4
        elif pkg['type'] == "P2_STEP_4":
            encrypted_data = pkg['data']
            decrypted_str = rsa.decrypt_string(encrypted_data, my_priv)
            print(f"\n[A] Menerima P2_STEP_4 dari B (SECRET KEY!). Decrypted: {decrypted_str}")
            parts = decrypted_str.split("||")
            des_secret_key = parts[1]
            start_des_chat()
            
        conn.close()

def send_p1_step_7(n2):
    msg = f"{n2}"
    ciphertext = rsa.encrypt_string(msg, peer_pub_key)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((PEER_B_IP, PEER_B_PORT))
        sock.sendall(serialize({"type": "P1_STEP_7", "data": ciphertext}))
        print(f"[A] Mengirim P1_STEP_7 ke B (N2 terenkripsi).")
    except:
        print("[A] Gagal konek ke B untuk Step 7.")
    finally:
        sock.close()
    time.sleep(1)
    start_protocol_2()

def send_p2_step_3(n2):
    msg = f"{n2}"
    ciphertext = rsa.encrypt_string(msg, peer_pub_key)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((PEER_B_IP, PEER_B_PORT))
    sock.sendall(serialize({"type": "P2_STEP_3", "data": ciphertext}))
    print(f"[A] Mengirim P2_STEP_3 ke B.")
    sock.close()

def start_protocol_2():
    print("\n--- MEMULAI PROTOKOL 2 (Distribusi Secret Key) ---")
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
    print("\n" + "="*60)
    print(f"      DES SECURE CHAT READY ({MY_ID})")
    print(f"      Secret Key Session: {des_secret_key}")
    print("="*60)
    
    def receive_chat():
        while True:
            try:
                data = pka_socket.recv(4096)
                if not data: break
                pkg = deserialize(data)
                if pkg.get('type') == 'DES_INCOMING':
                    sender = pkg['sender']
                    cipher_hex = pkg['content']
                    
                    # Decrypt DES (Confidentiality)
                    plaintext = des.decrypt(cipher_hex, des_secret_key)
                    
                    print(f"\n[PESAN DITERIMA DARI {sender}]")
                    print(f"  + Ciphertext (DES): {cipher_hex}")
                    print(f"  + Plaintext       : {plaintext}") 

                    # [TRANSPARANSI VERIFIKASI]
                    signature_blocks = pkg.get('signature')
                    if signature_blocks:
                        print(f"  ------------------------------------------------")
                        print(f"  [RSA-VERIFY] Memverifikasi Signature {sender}...")
                        print(f"  [RSA-VERIFY] Public Key Pengirim: {peer_pub_key}")
                        print(f"  [RSA-VERIFY] Signature Block (Raw): {signature_blocks[:5]}... (truncated)")
                        
                        try:
                            # Decrypt Signature menggunakan Public Key LAWAN
                            # Diagram Kanan: Decryption Algorithm (PUb) -> Message
                            verified_msg = rsa.decrypt_string(signature_blocks, peer_pub_key)
                            print(f"  + Hasil Decrypt Signature: '{verified_msg}'")
                            
                            if verified_msg == plaintext:
                                print(f"  + STATUS: [VALID] ✅ Pesan otentik dari {sender}.")
                            else:
                                print(f"  + STATUS: [INVALID] ❌ Isi pesan berbeda dengan tanda tangan!")
                        except Exception as e:
                            print(f"  + STATUS: [ERROR] Gagal verifikasi: {e}")
                    else:
                        print(f"  + STATUS: [WARNING] Pesan ini tidak memiliki tanda tangan digital.")
                    
                    print("------------------------------------------------")
                    print("[REPLY] > ", end="", flush=True)
            except Exception as e:
                break

    threading.Thread(target=receive_chat, daemon=True).start()
    
    # Loop Kirim Pesan
    while True:
        msg = input(f"[{MY_ID}] Ketik Pesan: ")
        if msg.lower() == 'exit': break
        
        # [TRANSPARANSI SIGNING]
        # Diagram Kiri: Message Source -> Encryption (PRa) -> Y
        print(f"\n[RSA-SIGN] Signing message dengan Private Key {MY_ID}...")
        print(f"[RSA-SIGN] Private Key: {my_priv}")
        
        signature_blocks = rsa.encrypt_string(msg, my_priv)
        print(f"[RSA-SIGN] Signature generated (First 5 blocks): {signature_blocks[:5]}...")
        
        # Encrypt DES
        enc_hex = des.encrypt(msg, des_secret_key)
        print(f"[DES] Ciphertext generated: {enc_hex}")
        
        packet = {
            "type": "DES_MESSAGE",
            "target": TARGET_ID,
            "content": enc_hex,
            "signature": signature_blocks # Masukkan signature ke paket
        }
        pka_socket.sendall(serialize(packet))

def main():
    global pka_pub_key, peer_pub_key
    
    # Start Listener P2P
    threading.Thread(target=listen_for_peer, daemon=True).start()

    pka_socket.connect((PKA_IP, PKA_PORT))
    
    reg_packet = {"id": MY_ID, "pub_key": my_pub}
    pka_socket.sendall(serialize(reg_packet))
    
    resp = deserialize(pka_socket.recv(4096))
    pka_pub_key = tuple(resp['pka_pub'])
    print(f"[A] Terhubung PKA. PKA Public Key: {pka_pub_key}")
    
    input("Tekan Enter untuk memulai Protocol 1 (Minta Kunci B)...")
    
    # Start Protocol 1
    t1 = str(int(time.time()))
    req = {"type": "REQUEST_KEY", "target": TARGET_ID, "time": t1}
    pka_socket.sendall(serialize(req))
    print(f"[A] Protocol 1 Step 1: Request Key B sent.")
    
    resp = deserialize(pka_socket.recv(4096))
    if resp['type'] == "KEY_RESPONSE":
        signed_data = resp['data']
        decrypted_payload = rsa.decrypt_string(signed_data, pka_pub_key)
        print(f"[A] Protocol 1 Step 2: Balasan PKA (Verified): {decrypted_payload}")
        
        parts = decrypted_payload.split("||")
        key_str = parts[0] 
        peer_pub_key = eval(key_str) 
        
        print(f"[A] Public Key B didapat: {peer_pub_key}")
        
        # Step 3
        n1 = str(random.randint(1000, 9999))
        payload = f"{MY_ID}||{n1}"
        print(f"[A] Protocol 1 Step 3: Mengirim Nonce {n1} ke B...")
        encrypted_payload = rsa.encrypt_string(payload, peer_pub_key)
        
        sock_b = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock_b.connect((PEER_B_IP, PEER_B_PORT))
            sock_b.sendall(serialize({"type": "P1_STEP_3", "data": encrypted_payload}))
            sock_b.close()
        except ConnectionRefusedError:
            print("[ERROR] B belum online. Jalankan client_b.py dulu.")

    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
