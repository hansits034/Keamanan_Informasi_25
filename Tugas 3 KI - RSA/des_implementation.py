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