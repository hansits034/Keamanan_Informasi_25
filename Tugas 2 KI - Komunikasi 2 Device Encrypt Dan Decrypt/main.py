from des_implementation import DESImplementation

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