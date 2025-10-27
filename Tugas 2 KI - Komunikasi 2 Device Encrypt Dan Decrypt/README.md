# Komunikasi Terenkripsi DES (Python) Server dan Client

Ini adalah program komunikasi pesan sederhana yang mengimplementasikan enkripsi **DES (Data Encryption Standard)** murni menggunakan Python. Proyek ini mendemonstrasikan komunikasi Client-Server yang aman di mana semua pesan dienkripsi sebelum dikirim melalui jaringan.

Proyek ini menggunakan TCP Sockets (`socket.SOCK_STREAM`) untuk komunikasi yang andal dan berurutan, serta threading untuk memungkinkan pengiriman dan penerimaan pesan secara bersamaan.

## Struktur File

Berikut adalah penjelasan singkat untuk setiap file dalam proyek ini:

* `server.py`:
    Aplikasi sisi server. Bertugas mendengarkan koneksi masuk, menerima pesan terenkripsi, mendekripsinya, dan mengirim balasan terenkripsi.
* `client.py`:
    Aplikasi sisi klien. Bertugas terhubung ke server, mengirim pesan terenkripsi, dan menerima balasan terenkripsi dari server.
* `des_implementation.py`:
    Kelas implementasi DES. Mengurus padding, unpadding, konversi `bytes <-> hex`, dan memanggil proses inti DES.
* `des_logic.py`:
    Logika inti dari algoritma DES. Berisi implementasi struktur Feistel, fungsi F, permutasi, dan proses generasi subkey.
* `des_tables.py`:
    Berisi semua tabel konstanta yang diperlukan oleh DES.
* `main.py`:
    File utilitas terpisah untuk menguji fungsionalitas enkripsi dan dekripsi DES secara lokal tanpa perlu koneksi jaringan.

## Fitur Utama

* **Enkripsi End-to-End**: Seluruh komunikasi pesan dienkripsi menggunakan DES.
* **Implementasi Murni Python**: Tidak menggunakan library kriptografi eksternal (seperti `pycryptodome`). Seluruh algoritma DES dibangun dari awal.
* **Komunikasi Real-time**: Menggunakan TCP Sockets untuk koneksi yang stabil.
* **Chat Dua Arah (Full-Duplex)**: Menggunakan threading sehingga server dan klien dapat mengirim dan menerima pesan kapan saja tanpa harus menunggu giliran.
* **Output Informatif**: Program secara eksplisit menampilkan Plaintext, Ciphertext, dan Kunci yang digunakan untuk setiap pesan yang dikirim dan diterima, sangat baik untuk tujuan edukasi.

## Konfigurasi Kunci

Agar enkripsi dan dekripsi berfungsi, kunci rahasia harus sama di kedua file.

1.  Buka `server.py` dan atur variabel `KEY`.
2.  Buka `client.py` dan atur variabel `KEY` dengan nilai yang sama.

```python
# Di dalam server.py dan client.py
KEY = "mysecret" # Kunci harus tepat 8 karakter (8 byte / 64 bit)
```

## Cara Menjalankan

Anda dapat menjalankan program ini dalam dua skenario:

### Environment Logical (Tes di 1 Komputer)

Ini adalah cara termudah untuk menguji fungsionalitas.

1.  **Buka Terminal/CMD Pertama** dan jalankan `server.py`:
    ```bash
    python server.py
    ```
    Server akan menampilkan: `[SERVER] Mendengarkan di 127.0.0.1:12345...`

2.  **Buka Terminal/CMD Kedua** dan jalankan `client.py`:
    ```bash
    python client.py
    ```
    Client akan menampilkan: `[KONEKSI] Terhubung ke server di 127.0.0.1:12345`

3.  Sekarang Anda dapat mulai mengetik di terminal mana pun untuk mengirim pesan terenkripsi.


## Contoh Output (Sisi Server)

```bash
[SERVER] Mendengarkan di 127.0.0.1:12345...
[KONEKSI] ('127.0.0.1', 58536) terhubung.
[KIRIM PESAN]: ini adalah pesan dari server
   [MEMBALAS KE ('127.0.0.1', 58536)]
   > Plaintext : 'ini adalah pesan dari server'
   > Ciphertext: 49ad50fb07e62873fefd5d3ebfeb3e6d29279296e17c0a65ae6424d23dae699e
   > Kunci     : mysecret
[KIRIM PESAN]: 
[PESAN DARI ('127.0.0.1', 58536)]
  > Ciphertext: 49ad50fb07e62873fefd5d3ebfeb3e6d45fdd3fc49058678c0608318f02d9eb3
  > Kunci     : mysecret
  > Plaintext : 'ini adalah pesan dari client'
[BALAS PESAN] : 

```

## Contoh Output (Sisi Client)

```bash
[KONEKSI] Terhubung ke server di 127.0.0.1:12345
[KIRIM PESAN]: 
[PESAN DARI SERVER]
  > Ciphertext: 49ad50fb07e62873fefd5d3ebfeb3e6d29279296e17c0a65ae6424d23dae699e
  > Kunci     : mysecret
  > Plaintext : 'ini adalah pesan dari server'
[BALAS PESAN] : 
ini adalah pesan dari client
   [MENGIRIM KE SERVER]
   > Plaintext : 'ini adalah pesan dari client'
   > Ciphertext: 49ad50fb07e62873fefd5d3ebfeb3e6d45fdd3fc49058678c0608318f02d9eb3
   > Kunci     : mysecret
[KIRIM PESAN]: 
```
