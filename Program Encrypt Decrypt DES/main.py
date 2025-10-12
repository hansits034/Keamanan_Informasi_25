from des_logic import DES

class DESImplementation(DES):

    def _pad(self, data_bytes):
        """Menambahkan padding PKCS#7 ke data bytes."""
        pad_len = 8 - (len(data_bytes) % 8)
        padding = bytes([pad_len] * pad_len)
        return data_bytes + padding

    def _unpad(self, padded_bytes):
        """Menghapus padding PKCS#7 dari data bytes."""
        if not padded_bytes:
            return b''
        pad_len = padded_bytes[-1]
        if pad_len > 8 or pad_len == 0:
            return padded_bytes
        return padded_bytes[:-pad_len]

    def _bytes_to_hex(self, data_bytes):
        """Mengubah bytes menjadi string hex tanpa library."""
        return ''.join(f'{byte:02x}' for byte in data_bytes)

    def _hex_to_bytes(self, hex_string):
        """Mengubah string hex menjadi bytes tanpa library."""
        if len(hex_string) % 2 != 0:
            hex_string = '0' + hex_string
        byte_array = bytearray()
        for i in range(0, len(hex_string), 2):
            hex_byte = hex_string[i:i+2]
            try:
                byte_array.append(int(hex_byte, 16))
            except ValueError:
                raise ValueError("Input hex tidak valid.")
        return bytes(byte_array)

    def encrypt(self, plaintext, key):
        """Menenkripsi plaintext menggunakan kunci yang diberikan."""
        if len(key.encode('utf-8')) != 8:
            raise ValueError("Kunci harus tepat 8 byte (64 bit).")

        plaintext_bytes = plaintext.encode('utf-8')
        padded_plaintext = self._pad(plaintext_bytes)
        
        plaintext_bits = [int(b) for byte in padded_plaintext for b in format(byte, '08b')]
        key_bits = [int(b) for char in key.encode('utf-8') for b in format(char, '08b')]
        
        subkeys = self._generate_subkeys(key_bits)

        encrypted_bits = []
        for i in range(0, len(plaintext_bits), 64):
            block = plaintext_bits[i:i+64]
            encrypted_block = self._des_process(block, subkeys, is_decrypt=False)
            encrypted_bits.extend(encrypted_block)
            
        encrypted_bytes = bytearray()
        for i in range(0, len(encrypted_bits), 8):
            byte_str = ''.join(map(str, encrypted_bits[i:i+8]))
            encrypted_bytes.append(int(byte_str, 2))
        
        return self._bytes_to_hex(encrypted_bytes)

    def decrypt(self, ciphertext_hex, key):
        """Mendekripsi ciphertext menggunakan kunci yang diberikan."""
        if len(key.encode('utf-8')) != 8:
            raise ValueError("Kunci harus tepat 8 byte (64 bit).")
            
        ciphertext_bytes = self._hex_to_bytes(ciphertext_hex)
        ciphertext_bits = [int(b) for byte in ciphertext_bytes for b in format(byte, '08b')]
        key_bits = [int(b) for char in key.encode('utf-8') for b in format(char, '08b')]

        subkeys = self._generate_subkeys(key_bits)

        decrypted_bits = []
        for i in range(0, len(ciphertext_bits), 64):
            block = ciphertext_bits[i:i+64]
            decrypted_block = self._des_process(block, subkeys, is_decrypt=True)
            decrypted_bits.extend(decrypted_block)
            
        decrypted_bytes = bytearray()
        for i in range(0, len(decrypted_bits), 8):
            byte_str = ''.join(map(str, decrypted_bits[i:i+8]))
            decrypted_bytes.append(int(byte_str, 2))
            
        unpadded_bytes = self._unpad(decrypted_bytes)
        return unpadded_bytes.decode('utf-8')


# main
if __name__ == "__main__":
    des = DESImplementation()

    # Testing Default
    print("\n" + "="*50)
    print("Ini adalah bagian testing secara default untuk mengecek program error atau aman.\n")
    default_key = "mysecret"
    default_plaintext = "Ini adalah pesan rahasia yang akan dienkripsi menggunakan DES."

    print(f"Plaintext Asli: {default_plaintext}")
    print(f"Kunci          : {default_key}\n")
    
    # Enkripsi
    default_encrypted = des.encrypt(default_plaintext, default_key)
    print(f"Hasil Enkripsi (Hex):\n{default_encrypted}\n")

    # Dekripsi
    default_decrypted = des.decrypt(default_encrypted, default_key)
    print(f"Hasil Dekripsi:\n{default_decrypted}\n")

    # Verifikasi
    if default_plaintext == default_decrypted:
        print("Sama dengan hasil dekripsi.")
    else:
        print("Beda, Error!")
    
    print("\n" + "="*50)

    # Testing User Input
    print("Ini adalah bagian testing melalui user input, agar lebih mudah diuji.\n")
    
    while True:
        choice = input("Pilih mode (1: Enkripsi, 2: Dekripsi): ").strip()

        if choice == '1':
            plaintext = input("Masukkan teks yang akan dienkripsi: ")
            
            while True:
                key = input("Masukkan kunci (harus 8 karakter): ")
                if len(key.encode('utf-8')) == 8:
                    break
                print("Error: Kunci harus tepat 8 karakter. Silakan coba lagi.")
            
            try:
                encrypted_data = des.encrypt(plaintext, key)
                print("\n--- Hasil Enkripsi ---")
                print(f"Ciphertext (Hex): {encrypted_data}")
            except Exception as e:
                print(f"Error saat enkripsi: {e}")

        elif choice == '2':
            ciphertext_hex = input("Masukkan ciphertext (dalam format hex): ")
            
            while True:
                key = input("Masukkan kunci (harus 8 karakter): ")
                if len(key.encode('utf-8')) == 8:
                    break
                print("Error: Kunci harus tepat 8 karakter. Silakan coba lagi.")

            try:
                decrypted_data = des.decrypt(ciphertext_hex, key)
                print("\n--- Hasil Dekripsi ---")
                print(f"Plaintext Asli: {decrypted_data}")
            except ValueError as e:
                print(f"Error: {e}. Pastikan input hex valid.")
            except Exception as e:
                print(f"Terjadi kesalahan saat dekripsi: {e}")
        
        else:
            print("Pilihan tidak valid. Silakan pilih 1 atau 2.")

        try_again = input("\nApakah Anda ingin mencoba lagi? (y/n): ").lower()
        if try_again != 'y':
            print("Program Selesai, Program Berhanti.")
            break
        print("-" * 50)