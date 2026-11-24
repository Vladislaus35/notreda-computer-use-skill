# Computer Use Skill

Model-bağımsız ve güvenlik sertleştirmeli, tek başına kurulabilir **Bilgisayar Kullanımı (Computer Use) Agent Skill** paketi.

Harici `pip` bağımlılığı gerektirmez (yalnızca Python 3.9+ standart kütüphanesi). **Antigravity**, **Claude Code**, **Codex**, **Cursor** veya **OpenCode** ile doğrudan kullanılabilir.

---

## Özellikler

- **Model-Bağımsız:** Görsel (Vision) modellerle ekran görüntüsü + koordinat, metin modellerle pencere listesi + Win32 UI ağacı + klavye kısayolları ve DOM inceleme desteği.
- **Sıfır Harici Bağımlılık:** Windows 10/11 üzerinde saf `ctypes` Win32 API (`GDI BitBlt` + saf Python PNG kodlayıcı, `SendInput` Unicode klavye/fare, `EnumWindows` / `EnumChildWindows`, Win32 Pano). Linux X11 (`xdotool`/`wmctrl`/`scrot`/`xclip`) ve Wayland (`grim` + dürüst kısıt bildirimi) desteği.
- **3 Koordinat Uzayı:** `physical` (gerçek piksel), `scaled` (son ekran görüntüsü pikseli → otomatik fiziksel dönüşüm) ve `normalized` (`0..1000`).
- **Sertleştirilmiş Güvenlik & Gizlilik:**
  - Parola yöneticisi / kasa / oturum açma pencerelerinde (`KeePass`, `1Password`, `Bitwarden`, `Parola`, `Şifre`, `Vault`, `Sign in`) otomatik ekran görüntüsü ve UI okuma engeli.
  - `ES_PASSWORD` alan maskeleme + pano ve UI metinlerinde otomatik API anahtarı / token sansürleme.
  - Tehlikeli sistem kabukları (`cmd`, `powershell`, `regedit`, `diskpart`, `shutdown` vb.) ve kritik tuş kombinasyonları (`Ctrl+Alt+Delete`, `Win+R/X/L`, `Ctrl+Shift+Esc`) engelli.
  - SSRF korumalı web DOM inceleyici (bulut metadata IP engeli + en fazla 3 yönlendirme kontrolü).
  - Masaüstü dosya/klasör oluşturmada dizin dışına çıkış (`..`), symlink ve çalıştırılabilir dosya (`.exe`, `.bat`, `.ps1` vb.) engeli.
  - İsteğe bağlı `--allow-apps`, `--allow-domains`, `--allow-paths` izin listeleri.

---

## Kurulum (Installation)

Depoyu klonlayın ve kullandığınız ajanın `skills` klasörüne kopyalayın:

```bash
git clone https://github.com/Vladislaus35/notreda-computer-use-skill.git computer-use
```

### Antigravity
```powershell
# Global kurulum (Windows)
xcopy /E /I computer-use "%USERPROFILE%\.gemini\antigravity\skills\computer-use"
```
veya proje bazlı: `.agents/skills/computer-use/`

### Claude Code
```bash
# Global kurulum
cp -r computer-use ~/.claude/skills/computer-use
```

### Codex
```bash
cp -r computer-use ~/.codex/skills/computer-use
```

### Cursor
```bash
cp -r computer-use .cursor/skills/computer-use
```

---

## Hızlı Kullanım (CLI Test)

```powershell
# Platform yeteneklerini kontrol et
python scripts/computer_use_cli.py capabilities --json

# Açık pencereleri listele
python scripts/computer_use_cli.py inspect-windows --json

# Ekran görüntüsü yakala (max 1280px PNG)
python scripts/computer_use_cli.py capture-screen --json

# Güvenli uygulama başlat
python scripts/computer_use_cli.py open-app --app calc --json

# Aktif penceredeki UI kontrollerini oku
python scripts/computer_use_cli.py read-ui-elements --json

# Güvenli web sayfası DOM özeti çıkar
python scripts/computer_use_cli.py inspect-web-page --url https://example.com --json
```

---

## Dosya Yapısı

```text
.
├── SKILL.md                      # Ajanlar için ana Skill tanımı ve talimatları
├── scripts/
│   └── computer_use_cli.py       # Sıfır bağımlılıklı Windows/Linux Computer Use motoru
├── references/
│   ├── action-schema.md          # Yapısal computer_action JSON şeması
│   └── safety-policy.md          # Güvenlik, gizlilik, SSRF ve onay kuralları
├── README.md
└── LICENSE
```

## Lisans

MIT License — bkz. [LICENSE](LICENSE).
