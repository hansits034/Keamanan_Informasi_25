# Keamanan_Informasi_B_25
| NRP | Nama |
|----------|----------|
| 5025231034 | Hans Sanjaya Yantono|

# Implementasi Data Encryption Standard (DES) dengan Python

Program ini adalah implementasi dari algoritma kriptografi **Data Encryption Standard (DES)** menggunakan bahasa pemrograman python. Tujuannya adalah untuk mendemonstrasikan alur kerja dan logika internal dari DES, mulai dari pembuatan kunci, permutasi, hingga proses enkripsi dan dekripsi.

## Struktur File

Terdiri dari tiga file:
* `main.py`: Berisi antarmuka pengguna untuk melakukan enkripsi dan dekripsi, serta fungsi-fungsi pembantu seperti padding dan konversi format.
* `des_logic.py`: Mengandung logika inti dari algoritma DES, termasuk pembuatan subkunci, fungsi Feistel, dan proses enkripsi/dekripsi per blok.
* `des_tables.py`: Menyimpan semua tabel dan konstanta yang diperlukan oleh DES, seperti tabel permutasi dan S-Box, sesuai dengan PPT atau Materi Keamanan Informasi 03.

## Cara Kerja Program

Proses enkripsi program ini mengikuti alur standar algoritma DES.

### 1. Input dan Persiapan Data (`main.py`)
- **Input Pengguna**: Program meminta pengguna memasukkan plaintext dan sebuah kunci rahasia sepanjang 8 karakter (64 bit).
- **Padding**: Karena DES hanya memproses data dalam blok 64-bit, plaintext yang ukurannya tidak pas akan ditambahkan padding menggunakan skema PKCS#7 agar data selalu penuh dalam satu blok.
- **Konversi ke Bit**: Plaintext dan kunci kemudian diubah menjadi urutan bit (list berisi 0 dan 1) untuk diproses.

### 2. Generasi Subkunci (`des_logic.py`)
Kunci utama 64-bit diproses untuk menghasilkan 16 subkunci 48-bit yang berbeda untuk setiap ronde enkripsi.
1.  [cite_start]**Permuted Choice 1 (PC-1)**: 56 bit dari kunci utama dipilih berdasarkan Materi KI03.
2.  [cite_start]**Pembagian & Pergeseran**: Kunci 56-bit dibagi dua (C dan D), lalu digeser ke kiri sesuai jadwal SHIFT_SCHEDULE berdasarakan Materi KI03.
3.  [cite_start]**Permuted Choice 2 (PC-2)**: Dari hasil pergeseran, 48 bit dipilih untuk menjadi subkunci ronde tersebut berdasarkan Materi KI03.

### 3. Proses Enkripsi per Blok (`des_logic.py`)
Setiap blok plaintext 64-bit melewati proses berikut:
1.  [cite_start]**Permutasi Awal (IP)**: Urutan bit dalam blok diacak menggunakan tabel INITIAL_PERMUTATION berdasarkan Materi KI03.
2.  **16 Ronde Feistel**: Blok melewati 16 ronde pemrosesan. Dalam setiap ronde, blok dibagi dua (Kiri/L dan Kanan/R). Bagian kanan diproses oleh (Fungsi F) bersama subkunci, hasilnya di-XOR dengan bagian kiri, lalu posisi kanan dan kiri ditukar.
3.  **Fungsi F (F-Function)**:
    - [cite_start]**Ekspansi (E)**: Bagian kanan (32 bit) diperluas menjadi 48 bit berdasarkan Materi KI03.
    - **XOR**: Hasilnya di-XOR dengan subkunci ronde.
    - [cite_start]**Substitusi S-Box**: Hasil 48-bit dipecah dan dimasukkan ke dalam 8 S-Box berdasarkan Materi KI03, mengubah 48-bit menjadi 32-bit. Ini adalah langkah kunci yang membuat DES aman.
    - [cite_start]**Permutasi (P)**: Hasil 32-bit diacak lagi menggunakan P_BOX berdasarkan Materi KI03.
4.  [cite_start]**Permutasi Final (FP)**: Setelah 16 ronde, hasilnya digabungkan kembali dan diacak untuk terakhir kali menggunakan FINAL_PERMUTATION berdasarkan Materi KI03.

### Proses Dekripsi
Proses dekripsi identik dengan enkripsi. Perbedaannya hanya urutan penggunaan subkunci yang dibalik.

## Cara Menjalankan Program
1.  Pastikan Anda memiliki Python 3.
2.  Letakkan file `main.py`, `des_logic.py`, dan `des_tables.py` dalam satu direktori.
3.  Buka terminal/CMD, navigasikan ke direktori tersebut.
4.  Jalankan perintah:
    ```sh
    python main.py
    ```
5.  Ikuti instruksi yang muncul di layar.
