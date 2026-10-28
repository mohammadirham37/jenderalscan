# PRD — JenderalScan

Oct 27, 2026 · @Mohammad Irham Akbar

Desktop web vulnerability scanner · Go

## Ringkasan Produk

JenderalScan adalah aplikasi desktop lintas platform (Windows, macOS, Linux) untuk memindai permukaan keamanan sebuah website yang kamu miliki atau yang sudah mengizinkanmu mengetesnya. Fokusnya pada deteksi non-intrusif: menemukan kelemahan konfigurasi, bukan mengeksploitasinya.

Aplikasi membungkus beberapa pemeriksaan keamanan umum (security headers, konfigurasi TLS, fingerprint teknologi + pencocokan CVE, flag cookie, CORS, dan paparan file/path sensitif) dalam satu GUI, sehingga pentester, developer, dan admin tidak perlu merangkai banyak CLI tool terpisah. Dibangun dengan Go agar bisa menjalankan ratusan pemeriksaan paralel dan didistribusikan sebagai satu binary tanpa dependency runtime.

## Latar Belakang & Masalah

Pemeriksaan keamanan dasar sebuah website hari ini tersebar di banyak tool CLI terpisah (nuclei, httpx, testssl.sh, gobuster, dan lainnya). Untuk audit cepat, pengguna harus menginstal, mempelajari flag, dan menyatukan output masing-masing secara manual. Ini menyulitkan developer dan admin yang bukan spesialis keamanan.

Masalah yang ingin diselesaikan JenderalScan:

- **Fragmentasi tool.** Tidak ada satu antarmuka yang menyatukan pemeriksaan permukaan paling umum untuk pengguna non-CLI.
- **Hambatan setup.** Kebanyakan tool berbasis terminal; instalasi dan rangkaian dependency jadi penghalang.
- **Output mentah.** Hasil CLI sulit dibaca, dibandingkan antar scan, dan dilaporkan ke stakeholder non-teknis.
- **Kurang guardrail.** Tool umum tidak memaksakan konfirmasi izin, sehingga mudah dipakai menyalahi aturan tanpa sengaja.

JenderalScan mengisi celah ini dengan GUI desktop yang ramah, hasil terstruktur yang bisa diekspor, dan alur yang menegaskan penggunaan legal sejak awal.

## Tujuan & Non-Tujuan

**Tujuan**

- Menyediakan audit permukaan keamanan website lewat satu GUI desktop, tanpa setup CLI.
- Mencakup pemeriksaan non-intrusif paling umum dalam satu kali scan.
- Menyajikan hasil terstruktur, berperingkat severity, dengan penjelasan dan rekomendasi perbaikan.
- Mengekspor laporan (JSON, HTML, PDF) yang bisa dibagikan ke stakeholder teknis maupun non-teknis.
- Menegakkan penggunaan yang sah lewat konfirmasi izin sebelum scan.

**Non-Tujuan (eksplisit di luar lingkup)**

- **Bukan tool serangan.** Tidak menyediakan exploit, payload penyerang, brute-force kredensial, atau modul untuk mengambil alih sistem.
- Tidak melakukan pengujian intrusif/destruktif (SQLi/RCE aktif, DoS, fuzzing yang membebani target).
- Tidak menjadi pengganti pentest manual menyeluruh atau WAF/SIEM.
- Tidak melakukan scanning massal tanpa pembatasan rate terhadap target pihak ketiga.
- Tidak menyimpan atau mengirim data target ke server eksternal (semua proses lokal pada versi awal).

## Pengguna Target

| Persona | Konteks | Yang dibutuhkan dari JenderalScan |
| --- | --- | --- |
| Developer / DevOps | Memeriksa aplikasi sendiri sebelum rilis | Scan cepat, rekomendasi perbaikan yang actionable, integrasi ke alur kerja |
| Admin sistem / IT | Memantau aset web internal organisasi | Audit berkala, laporan yang bisa diarsipkan, batching beberapa host |
| Pentester / konsultan | Audit awal (recon) untuk klien yang sudah kontrak | Kecepatan, ekspor yang bisa masuk laporan, penanda scope/izin |
| Bug bounty hunter | Recon pada target yang masuk program resmi | Fingerprint + pencocokan CVE, kontrol rate agar sesuai aturan program |
| Mahasiswa / pembelajar keamanan | Belajar konsep keamanan web | Penjelasan tiap temuan, referensi (OWASP, CWE) |

Persona utama untuk MVP: **developer** dan **admin sistem** — pengguna yang paling terbantu oleh GUI dan paling sering memiliki wewenang penuh atas target.

## Ruang Lingkup & Batasan Legal

Memindai sistem tanpa izin dapat melanggar hukum (di Indonesia, antara lain UU ITE) dan aturan di banyak yurisdiksi lain. JenderalScan dirancang untuk hanya memindai target yang sah, dan desain produk harus mendorong hal itu secara aktif.

Guardrail yang menjadi bagian dari produk:

- **Konfirmasi izin sebelum scan.** Pengguna harus mencentang pernyataan bahwa mereka memiliki target atau memegang izin tertulis sebelum scan pertama pada sebuah host.
- **Default non-intrusif.** Semua modul default bersifat pasif/ringan; tidak ada mode destruktif.
- **Rate limiting bawaan.** Batas request per detik untuk mencegah beban berlebih yang bisa dianggap serangan.
- **Scope lock.** Scan dibatasi pada host/domain yang didaftarkan; subdomain atau host lain tidak ikut tanpa tindakan eksplisit.
- **Jejak audit.** Setiap scan mencatat waktu, target, dan modul yang dijalankan untuk akuntabilitas.
- **Disclaimer.** Aplikasi menampilkan pernyataan bahwa pengguna bertanggung jawab penuh atas legalitas penggunaan.

Lingkup pemeriksaan terbatas pada permukaan yang dapat diamati dari luar tanpa merusak atau menembus sistem. Pengujian yang membutuhkan eksploitasi aktif berada di luar lingkup produk ini.

## Kebutuhan Fungsional

Setiap modul berjalan independen dan menghasilkan temuan dengan severity (Info / Low / Medium / High), deskripsi, bukti, dan rekomendasi. Pengguna dapat memilih modul yang dijalankan.

| Modul | Yang diperiksa | Severity khas | Prioritas |
| --- | --- | --- | --- |
| Security headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy | Low–Medium | MVP |
| TLS/SSL | Versi protokol (TLS 1.0/1.1 usang), cipher lemah, masa & rantai sertifikat | Medium–High | MVP |
| Cookie flags | Secure, HttpOnly, SameSite pada setiap cookie | Low–Medium | MVP |
| Path sensitif | Keberadaan .git, .env, backup, file config, panel admin (wordlist, non-destruktif) | Medium–High | MVP |
| Tech fingerprint | Server, framework, CMS, bahasa, versi dari header & pola respons | Info | MVP |
| Pencocokan CVE | Memetakan versi software hasil fingerprint ke CVE yang diketahui | Medium–High | v1 |
| CORS | Konfigurasi Access-Control-\* yang terlalu permisif | Medium | v1 |
| Information disclosure | Error verbose, komentar HTML, metadata, directory listing | Low–Medium | v1 |
| DNS & subdomain | Record DNS, enumerasi subdomain pasif (sumber publik) | Info–Low | v2 |
| Port & service | Port umum terbuka pada host (scan ringan, terbatas) | Info–Medium | v2 |

Fitur pendukung lintas modul:

- **Profil scan** — preset (Quick / Full / Custom) menentukan modul & kedalaman.
- **Riwayat scan** — menyimpan hasil lokal untuk dibandingkan antar waktu (diff temuan baru vs lama).
- **Ekspor laporan** — JSON (mesin), HTML & PDF (dibagikan), dengan ringkasan severity.
- **Konfigurasi** — timeout, jumlah worker paralel, rate limit, custom header/user-agent, proxy.

## Arsitektur Teknis

JenderalScan berlapis: antarmuka desktop memanggil inti Go, yang mengorkestrasi Scan Engine untuk menjalankan modul-modul scanner secara paralel terhadap satu target.

&#91;embedded content: arsitektur berlapis · UI → inti → engine → modul → target\]

Setiap modul berjalan pada goroutine sendiri di bawah worker pool dengan rate limiter. Hasil dikumpulkan oleh inti, disimpan ke SQLite sebagai riwayat, dan diubah menjadi laporan. Desain modular membuat modul scanner baru bisa ditambahkan tanpa mengubah inti.

## Tech Stack

| Lapisan | Pilihan | Alasan |
| --- | --- | --- |
| Bahasa engine | Go | Concurrency ringan (goroutine), stdlib HTTP/TLS kuat, single static binary |
| GUI desktop | Wails (Go + frontend web) sebagai pilihan utama; Fyne sebagai alternatif native | Wails memberi UI modern berbasis web dengan backend Go; Fyne bila ingin murni Go tanpa WebView |
| Frontend (bila Wails) | Svelte atau React + Tailwind | Komponen UI cepat dibangun, tabel hasil yang responsif |
| HTTP client | net/http + kontrol timeout/retry | Tidak perlu dependency berat |
| Parsing HTML | golang.org/x/net/html atau goquery | Fingerprint & information disclosure |
| TLS checks | crypto/tls stdlib | Inspeksi protokol, cipher, sertifikat langsung |
| Data CVE | Dataset lokal (mis. snapshot NVD) + pembaruan berkala | Pencocokan offline, menghindari ketergantungan API saat scan |
| Penyimpanan lokal | SQLite (mis. modernc.org/sqlite, pure-Go) | Riwayat scan tanpa dependency C |
| Laporan | Template HTML bawaan + konversi PDF | Ekspor yang rapi dan dapat dibagikan |
| Build & rilis | GoReleaser + GitHub Actions | Cross-compile ke 3 OS, paket installer |

Rekomendasi: mulai dengan **Wails** untuk MVP karena mempercepat pembuatan UI yang kaya; evaluasi Fyne jika ingin menghindari WebView atau butuh binary lebih kecil.

## Kebutuhan UI/UX

Alur inti harus bisa diselesaikan dalam tiga langkah: masukkan target → pilih profil → lihat hasil.

Layar utama:

1. **Beranda / Scan baru** — input URL target, pemilih profil (Quick/Full/Custom), dan konfirmasi izin wajib sebelum tombol "Mulai Scan" aktif.
2. **Progres scan** — status per modul secara real-time (menunggu/berjalan/selesai), jumlah temuan berjalan, tombol batal.
3. **Hasil scan** — daftar temuan dikelompokkan per severity, dapat difilter dan dicari; klik temuan membuka detail (bukti, dampak, rekomendasi, referensi OWASP/CWE).
4. **Riwayat** — daftar scan terdahulu per target, dengan indikator temuan baru dibanding scan sebelumnya.
5. **Pengaturan** — worker paralel, rate limit, timeout, proxy, user-agent, pembaruan dataset CVE.

Prinsip UX:

- **Severity jelas secara visual** — warna dan ikon konsisten (High merah, Medium oranye, Low kuning, Info abu).
- **Setiap temuan actionable** — selalu ada "apa ini", "kenapa berisiko", "cara perbaiki".
- **Non-blocking** — UI tetap responsif saat scan berjalan (pekerjaan di goroutine, update via event).
- **Ekspor sekali klik** dari layar hasil.
- **Mode gelap & terang**, serta aksesibilitas dasar (kontras, navigasi keyboard).

## Kebutuhan Non-Fungsional

- **Performa.** Memanfaatkan concurrency Go; jumlah worker paralel dapat dikonfigurasi. Scan Quick pada satu host selesai dalam hitungan puluhan detik pada koneksi normal.
- **Keamanan aplikasi itu sendiri.** Tidak mengirim data target keluar perangkat; kredensial/proxy disimpan aman secara lokal; binary dapat diverifikasi (checksum/signing).
- **Portabilitas.** Satu binary per OS tanpa dependency runtime; mendukung Windows, macOS, dan Linux.
- **Keandalan.** Timeout dan retry yang tepat; kegagalan satu modul tidak menggagalkan seluruh scan; penanganan error jaringan yang jelas.
- **Sopan terhadap target.** Rate limit default yang wajar dan menghormati batas yang diset pengguna untuk menghindari beban berlebih.
- **Usability.** Dapat dipakai pengguna non-spesialis; teks dalam bahasa Indonesia dan Inggris.
- **Maintainability.** Arsitektur modular agar modul scanner baru mudah ditambah tanpa mengubah inti.
- **Privasi.** Riwayat scan hanya tersimpan lokal; pengguna dapat menghapusnya kapan saja.

## Roadmap & Milestone

Urutannya menahan fitur lanjutan sampai inti stabil: tiap fase punya gerbang kualitas yang harus lolos sebelum lanjut ke fase berikutnya.

&#91;embedded content: roadmap 4 fase · gerbang kualitas antar fase\]

MVP memvalidasi alur inti dan modul paling umum. v1 menambah pencocokan CVE, CORS, dan riwayat. v2 memperluas cakupan recon. Fase matang menambah otomasi dan distribusi. Perkiraan waktu bersifat indikatif, bukan komitmen jadwal.

## Metrik Keberhasilan

- **Adopsi** — jumlah unduhan dan pengguna aktif bulanan.
- **Penyelesaian scan** — persentase scan yang selesai tanpa error (target: >95%).
- **Akurasi** — tingkat false positive rendah pada modul inti, divalidasi terhadap target uji yang diketahui.
- **Kecepatan** — waktu rata-rata scan Quick per host memenuhi target performa.
- **Nilai yang dirasakan** — temuan yang ditindaklanjuti pengguna (mis. dari ekspor laporan yang dipakai).
- **Kualitas** — jumlah bug/crash yang dilaporkan per rilis menurun dari waktu ke waktu.

Untuk MVP, metrik utama yang dipantau: scan selesai tanpa error, waktu scan Quick, dan umpan balik kualitatif dari pengguna awal tentang kejelasan temuan.

## Risiko & Mitigasi

| Risiko | Dampak | Mitigasi |
| --- | --- | --- |
| Penyalahgunaan untuk scan tanpa izin | Hukum & reputasi | Konfirmasi izin wajib, default non-intrusif, rate limit, scope lock, jejak audit, disclaimer |
| False positive tinggi | Pengguna kehilangan kepercayaan | Validasi tiap modul terhadap target uji, tandai tingkat keyakinan temuan |
| Dataset CVE usang | Temuan tidak akurat | Mekanisme pembaruan dataset + tampilkan tanggal data |
| Scan membebani target | Dianggap serangan | Rate limit default konservatif, batas worker, mode throttle |
| Kompleksitas WebView lintas OS (Wails) | Hambatan rilis | Uji lebih awal di 3 OS; siapkan Fyne sebagai jalur alternatif |
| Scope membengkak | Rilis tertunda | Patuhi batas MVP; modul v1/v2 ditahan sampai inti stabil |
| Keliru masuk wilayah tool serangan | Risiko etis & kebijakan | Pertahankan Non-Tujuan sebagai batas desain yang keras; tolak fitur eksploitasi aktif |

Risiko paling penting adalah penyalahgunaan; mitigasinya bukan satu fitur melainkan rangkaian guardrail yang melekat pada alur produk sejak langkah pertama.
