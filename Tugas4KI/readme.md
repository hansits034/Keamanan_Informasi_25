# Simulasi Secure Chat (RSA Key Distribution & DES)

Proyek simulasi sistem komunikasi aman yang mengimplementasikan (RSA dan DES) from scratch tanpa menggunakan library kriptografi eksternal seperti `pycryptodome` atau `cryptography`.

Sistem ini mendemonstrasikan bagaimana dua klien (A dan B) yang belum saling percaya dapat bertukar Public Key melalui otoritas terpercaya Public-Key-Authority(PKA), melakukan negosiasi Secret Key (Session Key), dan akhirnya berkomunikasi menggunakan enkripsi simetris DES.

---

## 📂 Struktur File

### Core Library (Wajib ada di semua device)
1.  `rsa_manual.py`: Implementasi algoritma RSA (Keygen, Encrypt, Decrypt, Math logic) dari nol.
2.  `des_implementation.py`: Wrapper class untuk enkripsi/dekripsi string ke hex menggunakan DES.
3.  `des_logic.py`: Logika inti manipulasi bit dan struktur Feistel DES.
4.  `des_tables.py`: Tabel permutasi, S-Box, dan konstanta DES.

### Device Scripts
1.  `pka_server.py`: Skrip untuk Server/Authority. Menangani registrasi key dan relay pesan chat. Pakai mesin 1 Progjar Pak Roy localhost:60001.
2.  `client_a.py`: Skrip untuk Client 1 (A). Bertindak sebagai inisiator komunikasi. Pakai mesin 2 Progjar Pak Roy localhost:60002.
3.  `client_b.py`: Skrip untuk Client 2 (B). Bertindak sebagai responder. Pakai mesin 3 Progjar Pak Roy localhost:60003.

---

## 🌐 Topologi Jaringan

Simulasi ini dikonfigurasi untuk berjalan pada topologi jaringan berikut:

| Device | Role | IP Address | Port Utama | Port P2P |
| :--- | :--- | :--- | :--- | :--- |
| **Server** | Public Key Authority (PKA) & Relay | `172.16.16.101` | `12345` | - |
| **Client 1** | User A (Initiator) | `172.16.16.102` | - | `9002` |
| **Client 2** | User B (Responder) | `172.16.16.103` | - | `9003` |

> Catatan: Jika dijalankan di lokal (localhost), IP di dalam skrip client harus disesuaikan, namun logika protokol tetap sama.

---

## ⚙️ Cara Kerja Sistem (Protokol)

Sistem bekerja melalui 3 fase utama secara berurutan:

### Fase 1: Distribusi Public Key (via PKA)
Tujuannya adalah agar A mendapatkan Public Key B, dan B mendapatkan Public Key A secara terverifikasi.
<img width="698" height="718" alt="image" src="https://github.com/user-attachments/assets/69cebee0-305b-4ef0-8593-949ec95d3054" />

1.  **A -> PKA**: Request Public Key B (disertai Timestamp `T1`).
2.  **PKA -> A**: Mengirim data terenkripsi (Signed) berisi `[PublicKeyB || Request || T1]`.
    * *A mendekripsi pesan ini menggunakan Public Key PKA untuk memverifikasi keaslian.*
3.  **A -> B**: Mengirim pesan terenkripsi (menggunakan Public Key B) berisi `[ID-A || Nonce1]`.
4.  **B -> PKA**: Request Public Key A (disertai Timestamp `T2`).
5.  **PKA -> B**: Mengirim data terenkripsi (Signed) berisi `[PublicKeyA || Request || T2]`.
    * *B mendekripsi pesan ini menggunakan Public Key PKA.*
6.  **B -> A**: Mengirim pesan terenkripsi (menggunakan Public Key A) berisi `[Nonce1 || Nonce2]`.
    * *Ini membuktikan B adalah pemilik asli Public Key B karena bisa membaca Nonce1.*
7.  **A -> B**: Mengirim pesan terenkripsi (menggunakan Public Key B) berisi `[Nonce2]`.
    * *Autentikasi selesai.*

### Fase 2: Distribusi Secret Key (Session Key)
Setelah saling memiliki Public Key lawan, A dan B membuat jalur aman untuk membagikan kunci DES.
<img width="1258" height="982" alt="image" src="https://github.com/user-attachments/assets/73cd1f3f-cbd9-445a-914a-ff7b53434437" />


1.  **A -> B**: Mengirim `[Nonce1, ID-A]` (Terenkripsi Public Key B).
2.  **B -> A**: Mengirim `[Nonce1 || Nonce2]` (Terenkripsi Public Key A).
3.  **A -> B**: Mengirim `[Nonce2]` (Terenkripsi Public Key B).
4.  **B -> A**: Mengirim `[Nonce1, SecretKey]` (Terenkripsi Public Key A).
     Secret Key (8 karakter) digenerate oleh B dan dikirim ke A.

### Fase 3: Secure Chat (DES Encrypted)
Sekarang A dan B memiliki `SecretKey` yang sama.

1.  User mengetik pesan di terminal A atau B.
2.  Pesan dienkripsi menggunakan DES dengan `SecretKey`.
3.  Ciphertext (Hex) dikirim ke Server (Relay).
4.  Server meneruskan ciphertext ke tujuan.
5.  Penerima mendekripsi pesan menggunakan `SecretKey` yang sama.

---

## 🚀 Cara Menjalankan

Pastikan Python 3 sudah terinstall. Jalankan urutan berikut di 3 terminal berbeda:

### 1. Jalankan Server (PKA)
Server harus nyala duluan untuk mencatat registrasi key.
```bash
# Di Terminal Server (172.16.16.101)
python pka_server.py
```

### 2. Jalankan Client B (Responder)
Client B harus nyala agar siap menerima koneksi P2P dari A.
```# Di Terminal Client B (172.16.16.103)
python client_b.py
```

### 3. Jalankan Client A (Initiator)
Client A akan memulai proses handshake.
```# Di Terminal Client A (172.16.16.102)
python client_a.py
```
Tekan Enter di terminal Client A ketika diminta untuk memulai protokol.

