# Implementasi Zero Trust Security - Sistem Nilai Akademik

Repositori ini berisi implementasi dari tugas praktikum Keamanan Informasi mengenai **Zero Trust Security** pada level aplikasi. Sistem ini dibangun dengan arsitektur *microservices* dan mengimplementasikan prinsip-prinsip NIST SP 800-207 (*Never Trust Always Verify, Least Privilege, Assume Breach*).

**Nama:** Sixta Tabia Ritawan  
**NIM:** 247006111049  
**Mata Kuliah:** Keamanan Informasi 

---

### 1. Arsitektur PEP & PE (Bagian 3)
- **API Gateway (Port 3000):** Berperan sebagai *Policy Enforcement Point* (PEP) sekaligus *Policy Engine* (PE). Satu-satunya pintu masuk bagi *client*.
- **Service Nilai (Port 3001) & Service Transkrip (Port 3002):** Berjalan secara terpisah dan diakses secara eksklusif melalui API Gateway.

### 2. Autentikasi dan Token (Ketentuan 4.1)
- **Access Token:** Menggunakan JWT dengan masa berlaku 10 menit, memuat *payload* `sub` (user ID) dan `role`.
- **Refresh Token:** Disimpan di dalam basis data (SQLite) dengan masa berlaku 1 hari. Mendukung fitur **Pencabutan Sesi** secara permanen ketika user melakukan *Logout* (`POST /auth/logout`).
- **Token Service:** Layanan dapat menerbitkan token khusus antar-layanan (role: `service`, durasi: 5 menit) melalui `POST /auth/service` berbekal *Client ID* dan *Secret*.
- **Assume Breach (Double Verification):** API Gateway meneruskan *request* dengan menyisipkan header `X-Gateway-Secret`. Setiap service memvalidasi keberadaan secret ini **sekaligus** memverifikasi ulang keabsahan tanda tangan token JWT secara mandiri.

### 3. Kebijakan Akses & Least Privilege (Ketentuan 4.2 - Tabel 3)
Sistem membatasi akses berdasarkan peran dan kepemilikan atribut data:
- **Dosen:** Hanya dapat melihat (`GET /nilai`) dan mengubah nilai (`PUT /nilai/:id`) pada kelas yang diampunya.
- **Mahasiswa:** Hanya dapat melihat nilai di kelasnya dan melihat transkrip miliknya sendiri (`GET /transkrip/:nim`).
- **Admin:** Memiliki hak istimewa khusus untuk melihat seluruh transkrip mahasiswa tanpa batasan kepemilikan NIM.
- **Service (Otentikasi Internal):** Endpoint `POST /transkrip/sinkron` menolak token milik *user* dan hanya menerima Token Service dari hasil finalisasi kelas. 

### 4. Verifikasi Konteks (Ketentuan 4.3)
- **Konteks Perangkat (Device ID):** Setiap rute wajib menyertakan header `X-Device-ID`. Akses ditolak jika *request* berasal dari perangkat yang tidak terdaftar di database untuk pengguna bersangkutan.
- **Konteks Jam Operasional:** Endpoint perubahan nilai dan finalisasi dibatasi secara ketat hanya dapat diakses pada jam kerja (pukul 07.00 - 21.00 WIB).

### 5. Pencatatan Audit Log (Ketentuan 4.4)
Setiap keputusan akses dari Gateway—baik yang diizinkan (*allow*) maupun ditolak (*deny*)—dicatat secara terpusat ke dalam tabel `AuditLog` di database. Rekaman mencakup 6 variabel wajib: **Waktu, Subjek, Endpoint, Device, Hasil Keputusan, dan Alasan penolakan/izin**.

---

##  Cara Menjalankan Sistem

Pastikan **Node.js** dan **npm** sudah terinstal. Sistem ini menggunakan **SQLite** (melalui Prisma ORM) sehingga tidak memerlukan *server database* terpisah.

### 1. Instalasi dan Persiapan Data Seed (Ketentuan 5)
Buka terminal di *root* proyek dan jalankan:
```bash
npm install
npx prisma db push
node seed.js
```
*(Perintah `node seed.js` akan mengisi database dengan spesifikasi wajib: 1 admin, 2 dosen, 3 mahasiswa, 2 kelas dengan dosen berbeda, dan 1 device untuk masing-masing user).*

### 2. Menjalankan Layanan (Microservices)
Sistem membutuhkan tiga layanan berjalan bersamaan. Buka 3 terminal terpisah:

**Terminal 1 (Gateway):**
```bash
cd api-gateway
node index.js
```
**Terminal 2 (Service Nilai):**
```bash
cd service-nilai
node index.js
```
**Terminal 3 (Service Transkrip):**
```bash
cd service-transkrip
node index.js
```

---

##  Daftar Akun dan Device ID (Data Seed)

Seluruh pengujian dilakukan menggunakan Postman dengan menembak `http://localhost:3000`. Wajib menyertakan header **`X-Device-ID`** pada setiap pengujian (kecuali untuk menguji penolakan konteks).

| Role | Username | Password | Device ID Wajib (`X-Device-ID`) | Keterangan |
| :--- | :--- | :--- | :--- | :--- |
| **Admin** | `admin1` | `rahasia123` | `dev-admin-1` | Dapat melihat seluruh transkrip mahasiswa. |
| **Dosen** | `dosen1` | `rahasia123` | `dev-dosen-1` | Pengampu Kelas A (ID: 1). |
| **Dosen** | `dosen2` | `rahasia123` | `dev-dosen-2` | Pengampu Kelas B (ID: 2). |
| **Mahasiswa**| `mhs1` | `rahasia123` | `dev-mhs-1` | Terdaftar di Kelas A. |
| **Mahasiswa**| `mhs2` | `rahasia123` | `dev-mhs-2` | Terdaftar di Kelas A. |
| **Mahasiswa**| `mhs3` | `rahasia123` | `dev-mhs-3` | Terdaftar di Kelas B. |

> *Catatan:* Untuk proses Finalisasi Kelas, sistem secara *backend* menggunakan Client ID: `service-nilai` dan Secret: `rahasia-nilai-123` untuk memanggil `/auth/service` tanpa keterlibatan pengguna.

---
