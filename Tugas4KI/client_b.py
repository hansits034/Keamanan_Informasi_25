import socket
import threading
import time
import random
import string
from rsa_manual import RSAManual, serialize, deserialize
from des_implementation import DESImplementation

# IP Server PKA (Authority)
PKA_IP = '172.16.16.101' 
PKA_PORT = 12345

# Identitas Diri
MY_ID = "ID-B"
MY_LISTEN_PORT = 9003

# Identitas & IP Target (Client A)
TARGET_ID = "ID-A"
PEER_A_IP = '172.16.16.102' 
PEER_A_PORT = 9002

rsa = RSAManual()
print("\n" + "="*60)
print(f" GENERATING RSA KEYS FOR {MY_ID}...")
my_pub, my_priv = rsa.generate_keypair()
print(f" [RSA INFO] Public Key (e, n)  : {my_pub}")
print(f" [RSA INFO] Private Key (d, n) : {my_priv}")
print("="*60 + "\n")

pka_pub_key = None
peer_pub_key = None
des_secret_key = None
pka_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def generate_secret_key():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=8))

def listen_for_peer():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(('0.0.0.0', MY_LISTEN_PORT))
    listener.listen()
    print(f"[B] Mendengarkan pesan dari A di port {MY_LISTEN_PORT}...")

    while True:
        conn, addr = listener.accept()
        data = conn.recv(8192)
        if not data: continue
        pkg = deserialize(data)
        
        if pkg['type'] == "P1_STEP_3":
            encrypted = pkg['data']
            decrypted = rsa.decrypt_string(encrypted, my_priv)
            print(f"\n[B] Menerima P1_STEP_3 dari A. Decrypted: {decrypted}")
            parts = decrypted.split("||")
            n1 = parts[1]
            request_key_a(n1)
            
        elif pkg['type'] == "P1_STEP_7":
            encrypted = pkg['data']
            decrypted = rsa.decrypt_string(encrypted, my_priv)
            print(f"\n[B] Menerima P1_STEP_7 (N2) dari A. Verified: {decrypted}")
            print("[B] PROTOCOL 1 SELESAI. Key Exchange aman.")
            
        elif pkg['type'] == "P2_STEP_1":
             encrypted = pkg['data']
             decrypted = rsa.decrypt_string(encrypted, my_priv)
             print(f"\n[B] Menerima P2_STEP_1 dari A. Isi: {decrypted}")
             parts = decrypted.split("||")
             n1 = parts[0]
             send_p2_step_2(n1)

        elif pkg['type'] == "P2_STEP_3":
             encrypted = pkg['data']
             decrypted = rsa.decrypt_string(encrypted, my_priv)
             print(f"\n[B] Menerima P2_STEP_3 dari A (N2 Verified).")
             send_p2_step_4() 
             
        conn.close()

def request_key_a(n1_from_a):
    global peer_pub_key
    t2 = str(int(time.time()))
    req = {"type": "REQUEST_KEY", "target": TARGET_ID, "time": t2}
    pka_socket.sendall(serialize(req))
    print(f"[B] Protocol 1 Step 4: Request Key A sent ke PKA.")
    
    resp = deserialize(pka_socket.recv(4096))
    if resp['type'] == "KEY_RESPONSE":
        signed_data = resp['data']
        decrypted = rsa.decrypt_string(signed_data, pka_pub_key)
        print(f"[B] Protocol 1 Step 5: Balasan PKA (Verified): {decrypted}")
        parts = decrypted.split("||")
        key_str = parts[0]
        peer_pub_key = eval(key_str)
        print(f"[B] Public Key A didapat: {peer_pub_key}")
        
        n2 = str(random.randint(1000, 9999))
        payload = f"{n1_from_a}||{n2}"
        ciphertext = rsa.encrypt_string(payload, peer_pub_key)
        print(f"[B] Protocol 1 Step 6: Mengirim N1 & N2 ke A...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((PEER_A_IP, PEER_A_PORT))
        sock.sendall(serialize({"type": "P1_STEP_6", "data": ciphertext}))
        sock.close()

def send_p2_step_2(n1):
    n2 = str(random.randint(1000, 9999))
    payload = f"{n1}||{n2}"
    ciphertext = rsa.encrypt_string(payload, peer_pub_key)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((PEER_A_IP, PEER_A_PORT))
    sock.sendall(serialize({"type": "P2_STEP_2", "data": ciphertext}))
    print(f"[B] Mengirim P2_STEP_2 ke A.")
    sock.close()

def send_p2_step_4():
    global des_secret_key
    des_secret_key = generate_secret_key()
    
    payload = f"VALID||{des_secret_key}"
    ciphertext = rsa.encrypt_string(payload, peer_pub_key)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((PEER_A_IP, PEER_A_PORT))
    sock.sendall(serialize({"type": "P2_STEP_4", "data": ciphertext}))
    print(f"[B] Mengirim P2_STEP_4 (SECRET KEY) ke A: {des_secret_key}")
    sock.close()
    
    start_des_chat()

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
                    plaintext = des.decrypt(cipher_hex, des_secret_key)
                    
                    print(f"\n[PESAN DITERIMA DARI {sender}]")
                    print(f"  + Ciphertext (DES): {cipher_hex}")
                    print(f"  + Plaintext       : {plaintext}")

                    # [TRANSPARANSI VERIFIKASI]
                    signature_blocks = pkg.get('signature')
                    if signature_blocks:
                        print(f"  ------------------------------------------------")
                        print(f"  [DIAGRAM STEP 3 & 4] VERIFYING SIGNATURE (Process Y -> X)")
                        print(f"  Using Sender's Public Key (PU_b): {peer_pub_key}")
                        print(f"  Formula: X = Y^e mod n")
                        
                        decrypted_chars = []
                        valid = True
                        
                        print(f"  [MATH PROCESS] Detail perhitungan per blok:")
                        for i, cipher_val in enumerate(signature_blocks):
                            # Rumus RSA Verify
                            val_m = pow(cipher_val, peer_pub_key[0], peer_pub_key[1])
                            char_m = chr(val_m)
                            decrypted_chars.append(char_m)
                            
                            if i < 3: 
                                print(f"    - Block {i}: {cipher_val} ^ {peer_pub_key[0]} mod {peer_pub_key[1]} = {val_m} ('{char_m}')")
                        
                        verified_msg = "".join(decrypted_chars)
                        print(f"  + Hasil Gabungan (X): '{verified_msg}'")

                        if verified_msg == plaintext:
                            print(f"  + STATUS: [VALID] Signature cocok dengan pesan asli.")
                        else:
                            print(f"  + STATUS: [INVALID] Signature palsu/rusak!")
                    else:
                        print(f"  + STATUS: [WARNING] Tidak ada signature.")
                    
                    print("------------------------------------------------")
                    print("[REPLY] > ", end="", flush=True)
            except: break

    threading.Thread(target=receive_chat, daemon=True).start()
    
    # Loop Kirim Pesan
    while True:
        msg = input(f"[{MY_ID}] Ketik Pesan: ")
        if msg.lower() == 'exit': break
        
        # [TRANSPARANSI SIGNING]
        print(f"\n[DIAGRAM STEP 1 & 2] CREATING SIGNATURE (Process X -> Y)")
        print(f"Using My Private Key (PR_a): {my_priv}")
        print(f"Formula: Y = X^d mod n")
        
        signature_blocks = []
        print(f"[MATH PROCESS] Detail perhitungan per karakter:")
        
        for i, char in enumerate(msg):
            # Rumus RSA Sign
            m_val = ord(char)
            c_val = pow(m_val, my_priv[0], my_priv[1])
            signature_blocks.append(c_val)
            
            if i < 3:
                print(f"  - Char '{char}' (Int {m_val}) -> {m_val}^{my_priv[0]} mod {my_priv[1]} = {c_val} (Block Y)")
        
        print(f"[RESULT] Signature Blocks (Y): {signature_blocks[:5]}...")
        
        # Encrypt DES
        enc_hex = des.encrypt(msg, des_secret_key)
        
        packet = {
            "type": "DES_MESSAGE",
            "target": TARGET_ID,
            "content": enc_hex,
            "signature": signature_blocks
        }
        pka_socket.sendall(serialize(packet))

def main():
    global pka_pub_key
    threading.Thread(target=listen_for_peer, daemon=True).start()
    pka_socket.connect((PKA_IP, PKA_PORT))
    reg_packet = {"id": MY_ID, "pub_key": my_pub}
    pka_socket.sendall(serialize(reg_packet))
    resp = deserialize(pka_socket.recv(4096))
    pka_pub_key = tuple(resp['pka_pub'])
    print(f"[B] Terhubung PKA. Menunggu request dari A...")
    while True: time.sleep(1)

if __name__ == "__main__":
    main()
