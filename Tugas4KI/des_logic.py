from des_tables import *

class DES:
    def _permute(self, block, table):
        """Melakukan permutasi pada blok berdasarkan tabel."""
        return [block[x-1] for x in table]

    def _string_to_bits(self, text):
        """Mengubah string menjadi array bit."""
        return [int(bit) for char in text.encode('utf-8') for bit in format(char, '08b')]

    def _bits_to_string(self, bits):
        """Mengubah array bit kembali menjadi string."""
        byte_array = bytearray()
        for i in range(len(bits) // 8):
            byte_bits = bits[i*8:(i+1)*8]
            byte_str = ''.join(map(str, byte_bits))
            byte_array.append(int(byte_str, 2))
        return byte_array.decode('utf-8', errors='ignore')

    def _xor(self, bits1, bits2):
        """Melakukan operasi XOR pada dua array bit."""
        return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

    def _left_circular_shift(self, bits, n):
        """Melakukan pergeseran sirkular ke kiri."""
        return bits[n:] + bits[:n]

    def _generate_subkeys(self, key_bits):
        """Menghasilkan 16 subkunci 48-bit dari kunci utama 64-bit."""
        permuted_key = self._permute(key_bits, PERMUTED_CHOICE_1) 
        c, d = permuted_key[:28], permuted_key[28:] 

        subkeys = []
        for i in range(16):
            shift_amount = SHIFT_SCHEDULE[i] 
            c = self._left_circular_shift(c, shift_amount) 
            d = self._left_circular_shift(d, shift_amount) 
            
            combined_cd = c + d
            subkey = self._permute(combined_cd, PERMUTED_CHOICE_2) 
            subkeys.append(subkey)
            
        return subkeys

    def _f_function(self, right_half, subkey):
        """Implementasi fungsi F dalam struktur Feistel."""
        expanded_right = self._permute(right_half, EXPANSION_TABLE) 
        xored = self._xor(expanded_right, subkey) 

        sbox_output = []
        for i in range(8):
            chunk = xored[i*6:(i+1)*6]
            row = int(str(chunk[0]) + str(chunk[5]), 2)
            col = int(''.join(map(str, chunk[1:5])), 2)
            
            val = S_BOXES[i][row][col] 
            sbox_output.extend([int(b) for b in format(val, '04b')])
            
        return self._permute(sbox_output, P_BOX) 

    def _des_process(self, block_bits, subkeys, is_decrypt=False):
        """Proses inti DES (enkripsi/dekripsi) untuk satu blok 64-bit."""
        permuted_block = self._permute(block_bits, INITIAL_PERMUTATION) 
        left, right = permuted_block[:32], permuted_block[32:] 

        if is_decrypt:
            subkeys = subkeys[::-1] 

        for i in range(16):
            new_left = right
            f_result = self._f_function(right, subkeys[i])
            new_right = self._xor(left, f_result)
            left, right = new_left, new_right

        final_block = right + left 
        

        return self._permute(final_block, FINAL_PERMUTATION)
