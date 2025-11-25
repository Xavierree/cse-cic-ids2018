# Xavierree — Intrusion Detection System (IDS)

Proyek ini mengimplementasikan sistem deteksi intrusi jaringan menggunakan algoritma Machine Learning (Logistic Regression, XGBoost, LightGBM) untuk mengklasifikasikan trafik jaringan sebagai *Benign* (Normal) atau berbagai jenis serangan (DDoS, Brute Force, Botnet, dll.). Dataset yang digunakan adalah CSE-CIC-IDS2018.

**Fitur Utama:**
- **Klasifikasi Multikelas**: Membedakan antara trafik normal dan beragam serangan.
- **Algoritma Teruji**: Logistic Regression, XGBoost, LightGBM.
- **Dapat Dijalankan di Google Colab atau Lokal**: Panduan khusus untuk Colab (disarankan) dan VS Code.

**Prasyarat**
- **Google Colab**: Akun Google untuk menjalankan notebook di Colab (direkomendasikan untuk akses GPU gratis).
- **Python 3.8+**: Untuk environment lokal.
- **Koneksi Internet Stabil**: Dataset lengkap berukuran besar (~16GB+).

**Menjalankan di Google Colab (Disarankan)**
1. Upload file `UAS_Final_Colab_keamanan_data_py (1).ipynb` ke Google Drive Anda.
2. Buka file tersebut dengan Google Colab.
3. Aktifkan GPU: menu `Runtime` > `Change runtime type` > pilih GPU (mis. T4) > `Save`.
4. Jalankan sel notebook secara berurutan.

Catatan penting:
- Pada bagian *Data Download*, notebook memakai `gdown` untuk mengunduh dataset dari Google Drive — pastikan sel ini berhasil. Jika link gdown tidak berfungsi, unduh dataset dari Kaggle (lihat bagian Dataset).

**Menjalankan di Lokal (VS Code)**
Persyaratan: RAM memadai (minimal 16GB disarankan 32GB) karena ukuran dataset sangat besar.

1) Setup environment
```
# Buat virtual environment (opsional tapi disarankan)
python -m venv venv

# Aktivasi virtual environment (Windows PowerShell)
venv\Scripts\Activate

# Install dependensi
pip install -r requirements.txt
```

2) Download dataset (CSE-CIC-IDS2018)
Opsi A — Kaggle API (direkomendasikan jika link gdown bermasalah):

1. Buat API token di profil Kaggle (`kaggle.json`).
2. Letakkan `kaggle.json` di `%USERPROFILE%\.kaggle\` (Windows).
3. Jalankan:
```
kaggle datasets download -d solarmainframe/ids-intrusion-csv
```
Ekstrak hasil unduhan ke folder `data/` di direktori proyek.

Opsi B — Download manual
1. Buka halaman dataset CSE-CIC-IDS2018 di Kaggle.
2. Unduh dan ekstrak isi ke `data/cse-cic-ids2018/`.

Struktur direktori yang diharapkan:
```
├── UAS_Final_Colab_keamanan_data_py (1).ipynb
├── requirements.txt
└── data/
    └── cse-cic-ids2018/
        ├── 02-14-2018.csv
        ├── ... (file csv lainnya)
```

3) Menjalankan Notebook di VS Code
- Instal ekstensi Jupyter di VS Code.
- Buka file `.ipynb` dan pilih kernel Python dari virtual environment (`venv`).
- Jalankan sel satu per satu.

**Parameter yang berguna**
- `SAMPLING_RATE`: Jika RAM terbatas, kurangi nilai ini (mis. ubah 1 menjadi 0.1 untuk menggunakan 10% data).

**Troubleshooting**
- MemoryError: Kurangi `SAMPLING_RATE`, atau gunakan Google Colab dengan GPU dan runtime yang lebih kuat.
- Gdown Error / Permission Denied: Gunakan Kaggle API atau unduh manual dari Kaggle.

**Konten File Penting**
- `UAS_Final_Colab_keamanan_data_py (1).ipynb`: Notebook utama berisi preprocessing, training, dan evaluasi model.
- `requirements.txt`: Daftar dependensi Python.
- `data/`: Folder dataset (tidak disertakan di repo karena besar).

**Tips**
- Gunakan Google Colab untuk percobaan awal atau saat RAM lokal terbatas.
- Untuk eksperimen cepat, kurangi `SAMPLING_RATE` atau gunakan subset dataset.

Jika Anda ingin, saya bisa:
- Menambahkan badge, lisensi, atau petunjuk setup Docker/Conda.
- Menyediakan skrip kecil untuk mengunduh subset dataset dan menjalankan contoh training cepat.

---
Nama proyek: **Xavierree — IDS CSE-CIC-IDS2018**
