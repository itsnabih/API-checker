# AGENT API.IO — Zero-Trace AI Agent API Debugger & Anti-Masking Forensics

Aplikasi web **100% Client-Side (Zero-Backend & Zero-Disk-Cache)** bergaya **[jwt.io](https://www.jwt.io/)** untuk menguji, memvalidasi, dan membedah metadata API LLM sebelum diimplementasikan ke AI Agent otonom seperti **Strix**, **Xalgorix**, LiteLLM, atau sistem agent lainnya.

---

## Fitur Utama

### 1. Desain Split-Pane Debugger Ala `jwt.io`
* **Magenta (`#fb015b`) — `HEADER: GATEWAY, PROTOCOL & QUOTA HEADERS`:** Menampilkan protokol aktif, Base URL ter-normalisasi, deteksi Gateway/Proxy, status CORS, latency (TTFB vs RTT), dan sisa kuota Rate-Limit (`x-ratelimit-*`).
* **Purple (`#d63aff`) — `PAYLOAD: MODEL METADATA & 7-STAGE AGENT SUITE`:** Menampilkan objek JSON metadata model (`requested_model` vs `actual_returned_model`, `owned_by`, `system_fingerprint`, `context_length`, kapabilitas) serta **7-Stage Agent Readiness Checklist** lengkap dengan *Redacted Raw Payload Inspector*.
* **Cyan (`#00b9f1`) — `VERIFY AUTHENTICITY & STRIX / XALGORIX EXPORTER`:** Menampilkan hasil analisis **Anti-Masking Forensics** dan generator konfigurasi siap copy-paste untuk **Strix**, **Xalgorix**, **`.env` / LiteLLM**, **JSON**, dan **cURL**.

### 2. Arsitektur Keamanan Zero-Trace & Anti-Sniffing (100% RAM-Only)
* **Zero Browser Storage:** Tidak pernah menyimpan API key atau secret ke `localStorage`, `sessionStorage`, `IndexedDB`, maupun `Cookies`.
* **Zero HTTP Disk Cache:** Semua pemanggilan `fetch()` dipaksa menggunakan `cache: "no-store"`, `credentials: "omit"`, dan `referrerPolicy: "no-referrer"` sehingga browser tidak menulis request/response ke folder `Cache_Data` di hardisk/SSD.
* **Anti-Password-Manager & Anti-Autofill:** Tidak menggunakan tag `<form>` maupun `type="password"` standar yang memicu database `Web Data` SQLite browser. Menggunakan masking CSS (`-webkit-text-security: disc`) dengan atribut `name` acak per sesi (`crypto.getRandomValues`).
* **Header-Only Auth:** Semua API key dikirim murni lewat HTTP Header (termasuk Google Gemini melalui `x-goog-api-key`, bukan query URL `?key=...`).
* **Zero External Script CDN:** Seluruh CSS dan JavaScript di-host secara lokal di dalam repositori dengan `Content-Security-Policy` (CSP) ketat.
* **Auto-Wipe Idle Timer & Clipboard Guard:** Otomatis menghapus secret dari RAM saat tab ditutup (`pagehide`/`beforeunload`) atau setelah idle, serta menghapus clipboard OS otomatis 30 detik setelah menyalin config ber-API key asli.

### 3. 7-Stage Agent Readiness & Anti-Masking Suite
1. **Stage 01 — Endpoint, CORS & Auth Handshake:** Validasi URL, status HTTP (`200` vs `401/403/429`), dan ekstraksi header gateway.
2. **Stage 02 — Model Registry & Spec Lookup (`/models`):** Mengecek ketersediaan model di daftar `/models` beserta spesifikasi `owned_by` & `context_length`.
3. **Stage 03 — Basic Chat Completion & Latency Breakdown:** Mengukur TTFB (Time-To-First-Byte), total RTT, kecepatan token/detik, dan rincian `usage`.
4. **Stage 04 — Server-Sent Events (SSE) Streaming Integrity:** Menguji `stream: true` dan validasi chunk SSE (`data: {...}`).
5. **Stage 05 — Agent Tool / Function Calling Validation:** Menguji pemanggilan tool (`check_target_port`) dan memvalidasi apakah model menghasilkan `tool_calls` berargumen JSON yang valid (wajib untuk **Strix** & **Xalgorix**).
6. **Stage 06 — Structured JSON Output & System Prompt Adherence:** Memastikan kepatuhan output JSON terstruktur.
7. **Stage 07 — Provider Authenticity & Anti-Masking Forensics:** Membandingkan model yang diminta vs snapshot model aktual yang dikembalikan server, mengecek keaslian perhitungan token (`usage`), fingerprint gateway, serta melakukan *Behavioral Identity Probe* untuk mendeteksi jika proxy memalsukan/menurunkan tier model.

---

## Cara Deploy ke GitHub Pages

Karena aplikasi ini menggunakan arsitektur **Zero-Build Static ES6 Modules**, Anda tidak membutuhkan Node.js atau proses build:

1. Buat repositori baru di GitHub (misal `agent-api-checker`).
2. Push seluruh file di folder ini ke branch `main`:
   ```bash
   git init
   git add .
   git commit -m "Initial commit: AGENT API.IO Zero-Trace Debugger"
   git branch -M main
   git remote add origin https://github.com/<username>/<repo-name>.git
   git push -u origin main
   ```
3. Buka repositori di GitHub $\rightarrow$ **Settings** $\rightarrow$ **Pages**.
4. Pada bagian **Build and deployment**:
   * **Source:** Pilih `Deploy from a branch`
   * **Branch:** Pilih `main` dan folder `/ (root)`, lalu klik **Save**.
5. Dalam 30–60 detik, aplikasi Anda langsung aktif di `https://<username>.github.io/<repo-name>/`.

---

## Cara Menjalankan Secara Lokal (+ Zero-Trace CORS Bridge)

Beberapa provider AI (seperti endpoint native `api.deepseek.com` atau *custom proxy* tertentu) memblokir request langsung dari browser karena tidak mengirimkan header CORS `Access-Control-Allow-Origin`.

Untuk menanggulanginya secara **100% Zero-Trace (tanpa membocorkan API key ke public proxy pihak ketiga)**:

### Opsi A — Menjalankan Local Zero-Log CORS Bridge (`cors-bridge.mjs`)
Cukup jalankan perintah berikut (hanya menggunakan built-in Node.js, tanpa `npm install`):

```bash
node cors-bridge.mjs
```

Script ini akan:
1. Melayani Web UI di `http://127.0.0.1:8787`
2. Menyediakan *Zero-Log RAM Relay* di `http://127.0.0.1:8787/proxy` (yang juga bisa diakses langsung dari halaman **GitHub Pages** Anda di komputer yang sama karena mendukung `Access-Control-Allow-Private-Network: true`).
3. Saat sebuah endpoint memblokir CORS browser, aplikasi otomatis melakukan **Auto-Failover** melewati bridge lokal tersebut tanpa menyimpan log apa pun.

### Opsi B — Deploy Private Cloudflare Worker (`cloudflare-worker.js`) untuk GitHub Pages
Jika Anda mengakses Web UI dari **GitHub Pages** dan ingin mengetes API non-CORS dari perangkat mana saja tanpa menjalankan Node lokal:
1. Buka dashboard **Cloudflare Workers & Pages** (Gratis) $\rightarrow$ **Create Worker**.
2. Copy-paste isi file `cloudflare-worker.js` lalu klik **Deploy**.
3. Masukkan URL Worker Anda (`https://nama-worker.<subdomain>.workers.dev/proxy`) ke kolom **Bridge URL** di menu **`+ Headers`** pada Web UI.
