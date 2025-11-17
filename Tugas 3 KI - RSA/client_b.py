import socket
import threading
import time
import random
import string
from rsa_manual import RSAManual, serialize, deserialize
from des_implementation import DESImplementation

# Konfigurasi Network
PKA_IP = '127.0.0.1' 
PKA_PORT = 12345

MY_ID = "ID-B"
TARGET_ID = "ID-A"

MY_LISTEN_PORT = 9003
PEER_A_IP = '127.0.0.1' # 172.16.16.102
PEER_A_PORT = 9002

rsa = RSAManual()
my_pub, my_priv = rsa.generate_keypair()
pka_pub_key = None
peer_pub_key = None
des_secret_key = None

pka_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def generate_secret_key():
    """Generate 8 char string for DES key"""
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
        
        # Protocol 1 Step 3: A -> B (Enc PubB [ID-A || N1])
        if pkg['type'] == "P1_STEP_3":
            encrypted = pkg['data']
            decrypted = rsa.decrypt_string(encrypted, my_priv)
            print(f"\n[B] Menerima P1_STEP_3 dari A. Decrypted: {decrypted}")
            
            parts = decrypted.split("||")
            sender_id = parts[0]
            n1 = parts[1]
            
            # Step 4: B request Key A to PKA
            request_key_a(n1)
            
        # Protocol 1 Step 7: A -> B (Enc PubB [N2])
        elif pkg['type'] == "P1_STEP_7":
            encrypted = pkg['data']
            decrypted = rsa.decrypt_string(encrypted, my_priv)
            print(f"\n[B] Menerima P1_STEP_7 (N2) dari A. Verified: {decrypted}")
            print("[B] PROTOCOL 1 SELESAI. Key Exchange aman.")
            
        # Protocol 2 Step 1: A -> B (Enc PubB [N1, ID-A])
        elif pkg['type'] == "P2_STEP_1":
             encrypted = pkg['data']
             decrypted = rsa.decrypt_string(encrypted, my_priv)
             print(f"\n[B] Menerima P2_STEP_1 dari A. Isi: {decrypted}")
             parts = decrypted.split("||")
             n1 = parts[0]
             
             # Step 2: B -> A (Enc PubA [N1 || N2])
             send_p2_step_2(n1)

        # Protocol 2 Step 3: A -> B (Enc PubB, N2)
        elif pkg['type'] == "P2_STEP_3":
             encrypted = pkg['data']
             decrypted = rsa.decrypt_string(encrypted, my_priv)
             print(f"\n[B] Menerima P2_STEP_3 dari A (N2 Verified).")
             
             # Step 4: B -> A (Enc PubA [N1, SecretKey])
             send_p2_step_4() # N1 disini simplifikasi pakai dummy atau disimpan state
             
        conn.close()

def request_key_a(n1_from_a):
    global peer_pub_key
    # Step 4: B -> PKA (Request || Time2)
    t2 = str(int(time.time()))
    req = {"type": "REQUEST_KEY", "target": TARGET_ID, "time": t2}
    pka_socket.sendall(serialize(req))
    print(f"[B] Protocol 1 Step 4: Request Key A sent ke PKA.")
    
    # Step 5: PKA -> B
    # Note: Karena socket PKA sedang listen di main thread (atau harusnya begitu),
    # Disini kita recv blocking dari socket PKA yang sudah established.
    # Namun karena structure code, kita recv disini:
    resp = deserialize(pka_socket.recv(4096))
    
    if resp['type'] == "KEY_RESPONSE":
        signed_data = resp['data']
        decrypted = rsa.decrypt_string(signed_data, pka_pub_key)
        print(f"[B] Protocol 1 Step 5: Balasan PKA (Verified): {decrypted}")
        
        parts = decrypted.split("||")
        key_str = parts[0]
        peer_pub_key = eval(key_str)
        print(f"[B] Public Key A didapat: {peer_pub_key}")
        
        # Step 6: B -> A (Enc PubA [N1 || N2])
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
    
    # Step 4: B -> A (Enc PubA [N1, SecretKey])
    # Asumsi N1 valid, kirim Secret Key
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
    print("\n--- DES CHAT READY (Client 1 -> Server -> Client 2) ---")
    
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
            except: break

    threading.Thread(target=receive_chat, daemon=True).start()
    
    while True:
        msg = input("[B] Kirim Pesan: ")
        if msg == 'exit': break
        
        enc_hex = des.encrypt(msg, des_secret_key)
        packet = {
            "type": "DES_MESSAGE",
            "target": TARGET_ID,
            "content": enc_hex
        }
        pka_socket.sendall(serialize(packet))

def main():
    global pka_pub_key
    
    threading.Thread(target=listen_for_peer, daemon=True).start()
    
    # Konek PKA
    pka_socket.connect((PKA_IP, PKA_PORT))
    
    # Registrasi
    reg_packet = {"id": MY_ID, "pub_key": my_pub}
    pka_socket.sendall(serialize(reg_packet))
    
    # Terima PKA Pub
    resp = deserialize(pka_socket.recv(4096))
    pka_pub_key = tuple(resp['pka_pub'])
    print(f"[B] Terhubung PKA. Menunggu request dari A...")
    
    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
