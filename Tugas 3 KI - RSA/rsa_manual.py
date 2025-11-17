import random

class RSAManual:
    def __init__(self):
        self.public_key = None
        self.private_key = None

    def gcd(self, a, b):
        while b != 0:
            a, b = b, a % b
        return a

    def multiplicative_inverse(self, e, phi):
        d = 0
        x1 = 0
        x2 = 1
        y1 = 1
        temp_phi = phi
        
        while e > 0:
            temp1 = temp_phi // e
            temp2 = temp_phi - temp1 * e
            temp_phi = e
            e = temp2
            
            x = x2 - temp1 * x1
            y = d - temp1 * y1
            
            x2 = x1
            x1 = x
            d = y1
            y1 = y
            
        if temp_phi == 1:
            return d + phi
        
    def is_prime(self, num):
        if num < 2: return False
        for i in range(2, int(num ** 0.5) + 1):
            if num % i == 0:
                return False
        return True

    def generate_keypair(self):
        # Menggunakan bilangan prima kecil agar simulasi cepat
        # Dalam produksi, gunakan p dan q yang sangat besar
        primes = [i for i in range(100, 300) if self.is_prime(i)]
        p = random.choice(primes)
        q = random.choice(primes)
        while p == q:
            q = random.choice(primes)
            
        n = p * q
        phi = (p-1) * (q-1)
        
        # Pilih e
        e = random.randrange(1, phi)
        g = self.gcd(e, phi)
        while g != 1:
            e = random.randrange(1, phi)
            g = self.gcd(e, phi)
            
        # Hitung d
        d = self.multiplicative_inverse(e, phi)
        
        # Public Key: (e, n), Private Key: (d, n)
        self.public_key = (e, n)
        self.private_key = (d, n)
        return ((e, n), (d, n))

    def encrypt_int(self, message_int, key):
        exp, n = key
        return pow(message_int, exp, n)

    def decrypt_int(self, cipher_int, key):
        exp, n = key
        return pow(cipher_int, exp, n)

    def encrypt_string(self, message, key):
        # Ubah string ke int, lalu enkripsi
        # Format output: list of integers (simulasi blok)
        encrypted_blocks = []
        for char in message:
            m = ord(char)
            c = self.encrypt_int(m, key)
            encrypted_blocks.append(c)
        return encrypted_blocks

    def decrypt_string(self, cipher_blocks, key):
        decrypted_chars = []
        for c in cipher_blocks:
            m = self.decrypt_int(c, key)
            decrypted_chars.append(chr(m))
        return "".join(decrypted_chars)

# Helper untuk mengubah list/tuple ke string agar bisa dikirim via socket
import json

def serialize(data):
    return json.dumps(data).encode('utf-8')

def deserialize(data):
    return json.loads(data.decode('utf-8'))
