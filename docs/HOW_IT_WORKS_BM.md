# Bagaimana ai-safe Berfungsi

Penerangan ringkas tentang cara ai-safe melindungi credential (password, API key, token, private key)
daripada AI coding agent seperti Claude Code, Cursor dan GitHub Copilot.

---

## Idea asas

AI **tidak pernah** diberi projek asal. AI hanya diberi **salinan yang sudah dibersihkan**, dalam folder
yang berasingan.

```
Repo asal (ada credential sebenar)              ← AI TIDAK sentuh
        │
        │  ai-safe buat salinan bersih
        │  (dijalankan oleh ai-safe, BUKAN oleh AI)
        ▼
Workspace AI (credential diganti placeholder)   ← AI bekerja di sini sahaja
        │
        │  AI siap → review automatik → developer luluskan sendiri
        ▼
Perubahan AI dimasukkan semula ke repo asal (credential asal kekal)
```

Contoh dalam repo asal:

```python
OPENAI_API_KEY = "sk-proj-abc123..."
```

Dalam workspace AI:

```python
OPENAI_API_KEY = "${AI_SAFE_SECRET_OPENAI_API_KEY}"
```

AI nampak *nama* credential, tetapi tidak nampak *nilai* sebenarnya.

---

## 1. Bagaimana ai-safe mengesan credential?

Dua pengesan (detector) berjalan serentak.

### a) Gitleaks

Gitleaks ialah tool open-source yang popular untuk mencari secret. Ia mempunyai ratusan rule untuk
format token yang dikenali, contohnya AWS, GitHub, Stripe dan Slack.

### b) Pengesan dalaman ai-safe (builtin)

Pengesan ini sentiasa berjalan sebagai lapisan kedua. Ia mencari:

- **Format token yang dikenali**: `sk-...` (OpenAI), `ghp_...` (GitHub), `AKIA...` (AWS),
  `-----BEGIN PRIVATE KEY-----`
- **Nama key yang mencurigakan**: `password = ...`, `api_key: ...`, `DB_PASSWORD=...`, `client_secret`
- **Konteks**:
  - `postgres://user:PASSWORD@host`
  - `mysql -pPASSWORD`
  - header `Authorization: Basic ...`
  - `?password=` dalam URL
  - connection string
  - Dockerfile `ENV`
  - heredoc dan komen
  - dan lain-lain
- **Rule custom** yang boleh ditambah oleh syarikat sendiri dalam `ai-safe.yaml`

Ia juga menapis *false positive*. Contohnya `password = os.environ["DB_PASSWORD"]` bukan secret, kerana
ia hanya rujukan kepada environment variable. `${VAR}` pula hanyalah placeholder.

### Di mana ia mencari?

- Fail yang di-track oleh Git
- Fail baru yang belum di-track (untracked)
- Fail yang di-ignore, contohnya `.env`
- Perubahan *staged* dan *unstaged*
- **Seluruh sejarah Git**: semua branch, semua tag, commit lama, fail yang sudah dipadam, dan juga
  commit message

---

## 2. Bila Gitleaks digunakan?

| Langkah | Apa yang Gitleaks scan |
|---|---|
| `scan` / `start` | Repo asal: fail (`gitleaks dir`), perubahan staged dan unstaged, seluruh sejarah (`gitleaks git --log-opts=--all`) |
| `verify` | Seluruh workspace AI, untuk memastikan tiada credential yang tertinggal |
| `review` | Fail yang diubah atau dicipta oleh AI |
| `integrate` | Scan terakhir pada hasil akhir, sebelum ditulis ke repo asal |

Gitleaks dijalankan dengan tetapan yang dikunci. Jika AI cuba meletakkan fail `.gitleaks.toml`,
`.gitleaksignore` atau komen `gitleaks:allow` untuk "menyorokkan" secret, semuanya akan diabaikan.

> **Penting:** Gitleaks hanya *mengesan*. Kerja *menggantikan* credential dibuat oleh enjin redaction
> ai-safe sendiri.

---

## 3. Bagaimana credential diganti? Adakah AI boleh baca di tengah-tengah proses?

**Tiada risiko pada peringkat ini, kerana AI belum berjalan langsung semasa proses ini.** Urutannya:

1. **Developer** menjalankan `ai-safe start` di terminal biasa. AI belum dibuka.
2. ai-safe membuat folder baru dengan nama rawak, dengan permission `0700` (hanya user itu boleh
   membukanya).
3. Untuk setiap fail, ai-safe:
   - membaca fail asal ke dalam **memori**,
   - menggantikan credential di dalam memori,
   - kemudian **menulis versi yang sudah bersih**.

   Fail **tidak pernah** ditulis dengan credential dahulu, lalu baru diganti. Jadi tiada saat di mana
   credential sebenar wujud dalam workspace.
4. Jika ai-safe **tidak pasti** ia boleh menggantikan credential dengan tepat (contohnya private key
   yang tidak lengkap, atau format yang pelik), fail itu **tidak disalin langsung**. Ini prinsip
   *fail closed*.
5. Fail sensitif tidak disalin langsung: `.env`, `*.pem`, `id_rsa`, `.aws/`, `credentials.json`,
   `.npmrc`, dan folder `.git`. Ini bermakna sejarah Git tidak boleh dibaca oleh AI.
6. **Verify** scan semula seluruh workspace. Jika ada sebarang masalah, workspace **dipadam terus** dan
   AI tidak mendapat apa-apa.
7. Hanya selepas verify **lulus**, ai-safe memaparkan lokasi workspace. Barulah developer membuka AI
   di situ.

### Lapisan tambahan: cap jari (fingerprint)

ai-safe menyimpan "cap jari" (HMAC) bagi setiap credential asal, **bukan nilainya**. Jika nilai
credential asal muncul semula dalam workspace walaupun tanpa sebarang pola (contohnya password yang
ditampal dalam fail nota), `verify` dan `review` tetap boleh mengesannya.

### Di mana credential sebenar disimpan?

- Tiada di mana-mana dalam workspace AI.
- Mapping (placeholder → cap jari) disimpan di `~/.local/state/ai-safe/`, iaitu di luar workspace, dengan
  permission `0600`.
- Mapping ini **tidak mengandungi nilai secret** secara default. Penyimpanan nilai hanya pilihan, dan
  jika diaktifkan ia mesti disulitkan dengan passphrase.

---

## 4. Selepas AI selesai bekerja

### `ai-safe review`

Membandingkan workspace dengan salinan asal (*snapshot*). Snapshot ini disimpan di luar workspace,
supaya AI tidak boleh mengubah "baseline". Review akan menyekat jika AI:

- menulis credential baru secara hardcode,
- menyalahgunakan placeholder, contohnya menukar `${AI_SAFE_SECRET_...}` kepada nilai rekaan,
- mengubah `.env` atau melemahkan `.gitignore`,
- mencipta symlink, hard link, fail binari, atau fail dalam folder yang di-ignore (contohnya `.venv/`),
- memasukkan aksara tersembunyi (kod ANSI atau bidi) yang boleh mengelirukan paparan.

### `ai-safe integrate`

Mesti dijalankan oleh **developer sendiri**, yang perlu menaip `apply` untuk meluluskan. Arahan ini
menolak untuk berjalan jika ia dikesan dijalankan oleh AI agent. Ia:

- hanya memasukkan perubahan AI; baris yang mengandungi credential asal kekal seperti sebelumnya,
- tidak sesekali memasukkan credential sebenar ke dalam baris yang ditulis oleh AI,
- **tidak membuat commit dan tidak membuat push**. Developer menyemak `git diff` dan membuat commit
  sendiri.

### Folder `.claude/` pasukan

- `.ai-safe/` dan `.claude/ai-safe/` tidak pernah di-scan dan tidak pernah disalin. Sebarang perubahan
  di bawahnya dalam workspace **menyekat** integrasi (`ai-safe-install`).
- Skill ai-safe sendiri dijana semula daripada templat, bukan disalin.
- Skill, command dan agent pasukan (`.claude/skills|commands|agents/`) di-scan, di-redact dan disalin.
  Perubahan AI pada fail ini boleh diintegrasi, tetapi sentiasa disertai **AMARAN** `agent-instructions`
  dan dipaparkan dalam diff kelulusan, kerana ia mengarahkan sesi AI akan datang dalam repo asal. Baca
  dengan teliti.
- `.claude/settings.json` pasukan digabungkan ke dalam tetapan yang dijana melalui *allowlist* sahaja
  (`permissions`, `model` dan beberapa kunci selamat). Kunci berbahaya seperti hooks, `env` dan pelayan
  MCP dibuang, dan peraturan *deny* ai-safe sentiasa menang. Fail ini tidak pernah diintegrasi semula.
  Laluan `.claude/` yang lain (termasuk `settings.local*.json`) kekal dikecualikan.

---

## 4a. `ai-safe open` dan `ai-safe resync`

### `ai-safe open`

Membuka workspace yang telah disahkan melalui menu: (1) AI agent CLI, (2) VSCode, (3) Docker yang hanya
mount workspace, atau (4) papar arahan sahaja. Ia:

- **tidak pernah** melancarkan apa-apa secara automatik. Ia melancar hanya selepas developer memilih
  dari menu, dan hanya jika `security.allow_ai_launch: true`. Jika tidak, ia hanya memaparkan arahan,
- menolak untuk berjalan dalam sesi AI agent, dan menolak workspace yang belum lulus verify,
- hanya menghantar pembolehubah persekitaran dalam `launch_env_allowlist` (serta `AI_SAFE_AGENT=1`)
  kepada proses yang dilancarkan.

### `ai-safe resync`

Membina semula workspace daripada repo asal terkini, di **lokasi yang sama**. Workspace baru dibina dan
disahkan dalam folder *staging* dahulu; tiada satu bait pun sampai ke workspace sebenar sebelum verify
lulus. Jika apa-apa gagal, workspace lama dan state sesi kekal tidak berubah. Tutup sesi AI dalam
workspace sebelum resync. Jika workspace masih ada perubahan yang belum diintegrasi, resync menolak:
jalankan `ai-safe integrate` dahulu, atau `ai-safe resync --discard` dan taip `discard` untuk membuang
perubahan itu. Arahan ini juga menolak untuk berjalan dalam sesi AI agent.

### Konfigurasi

`scanner.scan_ignored: false` bersama `sanitization.include_ignored_files: true` ditolak, kerana fail yang
di-ignore akan disalin tanpa di-scan. AI mesti bertanya kepada developer sebelum menukar `scan_ignored`,
dan tidak boleh membuka fail yang di-ignore untuk membuat keputusan.

---

## 5. Had yang perlu diketahui

1. **Pengesanan berasaskan pola tidak 100% sempurna.** Secret yang tiada pola atau nama yang dikenali
   boleh terlepas. Contohnya password rawak dalam variable bernama `x`, nilai yang di-encode (base64 dan
   sebagainya), atau secret di dalam fail binari.
2. **ai-safe tidak menghalang AI membaca fail lain di komputer.** Jika AI berjalan sebagai user yang sama
   dengan akses shell penuh, secara teknikal ia *boleh* membuka repo asal. Skill dan `settings.json`
   hanyalah arahan, bukan tembok keselamatan.

   **Isolasi sebenar memerlukan salah satu daripada:**
   - menjalankan AI dalam **container** yang hanya mount folder workspace, atau
   - menjalankan AI sebagai **user OS yang berasingan**.
3. **Jangan jalankan `ai-safe start`, `scan`, `sanitize`, `open` atau `resync` melalui AI** dalam repo asal, kerana AI itu sudah mempunyai akses ke
   repo asal. Developer patut menjalankannya sendiri di terminal.
4. **Credential yang pernah di-commit ke Git dianggap sudah terdedah.** ai-safe akan memberi amaran,
   tetapi credential itu **mesti di-rotate** (ditukar). Membersihkan workspace tidak memadam sejarah
   lama.

---

## Aliran kerja ringkas

```bash
# 1. Pasang (sekali sahaja)
./install.sh --global                    # atau: ./install.sh --local /path/projek

# 2. Developer, dalam repo asal, di terminal biasa
ai-safe start                            # scan → bersihkan → verify → papar lokasi workspace

# 3. Buka AI dalam workspace sahaja
ai-safe open                             # atau sendiri: cd <lokasi-workspace> && claude

# 4. Selepas AI siap
ai-safe review                           # semakan automatik

# 5. Developer, dalam repo asal
ai-safe integrate                        # taip 'apply' untuk luluskan
git diff                                 # semak, kemudian commit sendiri

# 6. Kemudian: kemas kini workspace daripada repo asal (lokasi sama; tutup sesi AI dahulu)
ai-safe resync

# 7. Bersihkan
ai-safe cleanup
```

---

## Ringkasan satu ayat

> ai-safe menggunakan Gitleaks dan pengesan dalaman untuk mencari credential dalam fail dan seluruh
> sejarah Git. Ia membina salinan projek yang telah dibersihkan dan disahkan sebelum AI dibuka, dan
> menyimpan credential asal di luar capaian AI. Perubahan AI hanya masuk ke repo sebenar selepas review
> automatik dan kelulusan manual developer. Isolasi penuh tetap memerlukan container atau user OS yang
> berasingan.

Untuk butiran teknikal lanjut, lihat [README.md](../README.md) dan [SECURITY.md](../SECURITY.md).
