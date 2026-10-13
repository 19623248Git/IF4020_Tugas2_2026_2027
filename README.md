# Venture128

Implementasi block cipher "baru" untuk Tugas 2 IF4020 Kriptografi. Venture128 menggunakan blok dan kunci 128 bit, 16 putaran, serta Type-2 Generalized Feistel Network dengan empat cabang. Program menyediakan CLI untuk enkripsi dan dekripsi teks atau berkas biner dalam mode ECB, CBC, CFB, OFB, dan CTR.

## Kebutuhan

- Python 3.14 atau lebih baru.
- uv untuk mengelola environment.
- Matplotlib untuk grafik histogram (dipasang otomatis oleh `uv sync`).
- Build backend menggunakan `uv build`.

## Menjalankan Program

Jalankan dari direktori repositori:

```sh
uv sync
uv run venture128 --help
```

Contoh penggunaan enkripsi teks dengan mode CBC:

```sh
uv run venture128 --block-mode cbc -e -key "0123456789abcdef" -s "timpa teks" -o cipher.bin
```

Dekripsi kembali ke berkas:

```sh
uv run venture128 --block-mode cbc -d -key "0123456789abcdef" -f cipher.bin -o hasil.txt
```

| Opsi | Keterangan |
| --- | --- |
| `--block-mode` | `ecb`, `cbc`, `cfb`, `ofb`, atau `ctr` |
| `-e` / `-d` | Enkripsi / dekripsi |
| `-key` | Kunci teks yang panjangnya tepat 16 byte setelah encoding UTF-8 |
| `-key-hex` | Kunci berupa 32 digit heksadesimal |
| `-key-file` | Membaca kunci dari berkas |
| `-s` / `-f` | Masukan teks / berkas |
| `-o` | Berkas keluaran; format default berupa byte mentah |
| `-of` | Format keluaran: `raw`, `hex`, atau `bits` |
| `--histogram` | Grafik PNG plaintext dan kelima mode, tanpa laporan terminal |

Untuk CBC, CFB, OFB, dan CTR, IV/counter awal dibuat otomatis dan disimpan di depan ciphertext. Saat dekripsi, program membacanya kembali. Jika menggunakan `-iv` secara manual, nilai tersebut harus diberikan kembali saat dekripsi. ECB tidak menggunakan IV.
