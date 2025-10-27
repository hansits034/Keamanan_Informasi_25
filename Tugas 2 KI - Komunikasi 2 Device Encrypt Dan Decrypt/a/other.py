# Konstanta DES
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

IP_INV = [40, 8, 48, 16, 56, 24, 64, 32,
           39, 7, 47, 15, 55, 23, 63, 31,
           38, 6, 46, 14, 54, 22, 62, 30,
           37, 5, 45, 13, 53, 21, 61, 29,
           36, 4, 44, 12, 52, 20, 60, 28,
           35, 3, 43, 11, 51, 19, 59, 27,
           34, 2, 42, 10, 50, 18, 58, 26,
           33, 1, 41, 9, 49, 17, 57, 25]

# Expansion Table (32 -> 48 bit)
E = [32, 1, 2, 3, 4, 5, 4, 5,
     6, 7, 8, 9, 8, 9, 10, 11,
     12, 13, 12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21, 20, 21,
     22, 23, 24, 25, 24, 25, 26, 27,
     28, 29, 28, 29, 30, 31, 32, 1]

# P-box (Permutation)
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

# S-box (8 buah)
SBOX = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
] * 8

# Fungsi Bantu Bit Manipulation
def permute(block, table):
    return ''.join(block[i - 1] for i in table)

def xor(a, b):
    return ''.join('0' if x == y else '1' for x, y in zip(a, b))

def sbox_substitution(bits):
    output = ""
    for i in range(8):
        chunk = bits[i * 6:(i + 1) * 6]
        row = int(chunk[0] + chunk[-1], 2)
        col = int(chunk[1:5], 2)
        val = SBOX[i][row][col]
        output += f"{val:04b}"
    return output

# Fungsi Utama DES Round
def f_function(R, K):
    R_expanded = permute(R, E)
    xored = xor(R_expanded, K)
    sboxed = sbox_substitution(xored)
    return permute(sboxed, P)

def generate_round_keys(key_64):
    keys = []
    for i in range(16):
        keys.append(key_64[i * 3:i * 3 + 48].ljust(48, '0'))
    return keys

# DES Encrypt
def des_encrypt(plain_text, key):
    plain_bits = ''.join(f"{ord(c):08b}" for c in plain_text)
    key_bits = ''.join(f"{ord(c):08b}" for c in key)[:64]

    permuted = permute(plain_bits, IP)
    L, R = permuted[:32], permuted[32:]
    round_keys = generate_round_keys(key_bits)

    for i in range(16):
        new_R = xor(L, f_function(R, round_keys[i]))
        L, R = R, new_R

    combined = R + L
    cipher_bits = permute(combined, IP_INV)
    return ''.join(chr(int(cipher_bits[i:i + 8], 2)) for i in range(0, len(cipher_bits), 8))

# DES Decrypt
def des_decrypt(cipher_text, key):
    cipher_bits = ''.join(f"{ord(c):08b}" for c in cipher_text)
    key_bits = ''.join(f"{ord(c):08b}" for c in key)[:64]

    permuted = permute(cipher_bits, IP)
    L, R = permuted[:32], permuted[32:]
    round_keys = generate_round_keys(key_bits)[::-1]

    for i in range(16):
        new_R = xor(L, f_function(R, round_keys[i]))
        L, R = R, new_R

    combined = R + L
    plain_bits = permute(combined, IP_INV)
    return ''.join(chr(int(plain_bits[i:i + 8], 2)) for i in range(0, len(plain_bits), 8))

# main
if __name__ == "__main__":
    print("=== DES ENCRYPT & DECRYPT ===\n")
    plaintext = input("Masukkan teks yang ingin dienkripsi: ")
    key = input("Masukkan kunci (maks 8 karakter): ")

    cipher = des_encrypt(plaintext, key)
    print("\nCiphertext:", cipher.encode('latin-1'))

    # Dekripsi
    decrypted = des_decrypt(cipher, key)
    print("Decrypted :", decrypted)