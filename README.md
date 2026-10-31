# Mute

Szerver nélküli, végpontok közötti titkosított chat, fájl- és mappaküldés. Windows + Linux.

## Futtatás
```
pip install -r requirements.txt
python mute.py          # Linuxon: sudo apt install python3-tk
```
Windows .exe: `build_windows.bat` → `dist\Mute.exe`
macOS .app: `bash build_mac.sh` → `dist/Mute.app` (Tkinteres Python kell: python.org telepítő vagy `brew install python-tk`;
az aláíratlan appot első indításkor jobb klikk → Megnyitás, vagy `xattr -dr com.apple.quarantine dist/Mute.app`)

## Hálózati módok
- **DIRECT**: IP:port (LAN, port forward, vagy bármilyen VPN – Tailscale/ZeroTier/WireGuard – IP-je).
- **TOR**: nincs port forward, NAT-on át megy, az IP-d nem látszik. Az app ideiglenes `.onion` címet generál
  (minden indításnál új). Ehhez kell a `tor`:
  - Windows: Tor Expert Bundle `tor.exe` → az app mellé a `tor\` mappába (vagy Tor Browser telepítve)
  - Linux: `sudo apt install tor`
  - macOS: `brew install tor` (vagy Tor Browser az /Applications mappában)
  Tor módban a kimenő kapcsolatok is Toron mennek (a partner sem látja az IP-det).

### Csatlakozás Toron át (nem kell ugyanazon a hálózaton lenni)
1. **A fél:** válassza a **TOR** módot → **START**. Pár másodperc után megjelenik az `xxxx.onion:5555` cím.
   Ezt és az ujjlenyomatot adja át B-nek egy *másik* csatornán.
2. **B fél:** válassza a **TOR** módot, írja/másolja a PEER mezőbe az onion címet → **CONNECT**
   (a Tort a CONNECT magától elindítja). Első alkalommal hasonlítsátok össze az ujjlenyomatot.
A cím minden indításkor új, és semmi nem mentődik, így nincs állandó azonosítód.

## Használat
1. Indítás → jelszó az identitáskulcshoz (üres = nincs).
2. Mód kiválasztása → **START**. A címedet (IP vagy .onion) és az ujjlenyomatodat add át a partnernek biztonságos csatornán.
3. A másik fél beírja a címedet → **CONNECT**. Első alkalommal ellenőrzitek az ujjlenyomatot.
4. Csoport: több partnerhez is csatlakozhatsz; az üzenet/fájl mindenkinek megy, akihez kapcsolódsz (teljes háló, nincs továbbítás: A–B és A–C kapcsolatnál B és C nem lát egymást).
5. Nagy fájl: 256 KB-os darabok, sebesség/ETA. Mappa: automatikusan zip. Fogadás: `Downloads/Mute`.
6. **wipe**: chat törlése. **PANIC**: chat törlés + kapcsolatok bontása + kilépés. **amnesia**: nem ment ismert partnereket.

## Titkosítás
- Handshake: **Noise_XX_25519_ChaChaPoly_SHA256** (`noiseprotocol` könyvtár). Kölcsönös hitelesítés,
  forward secrecy, és az identitáskulcsok **titkosítva** mennek át a vezetéken (egy hallgatózó nem látja, ki beszél).
- Átvitel: ChaCha20-Poly1305, 512 keretenként kulcsléptetés (rekey), a régi kulcs törlődik.
- Identitás: X25519 kulcs, opcionálisan jelszóval védve (scrypt + ChaCha20-Poly1305).
- Az ujjlenyomat a statikus publikus kulcs SHA-256 hash-ének első 128 bitje. **Ezt kell egy másik csatornán összevetni.**
- A korábbi (v2) verzióval nem kompatibilis; az ujjlenyomatok megváltoznak.

## Mit véd és mit nem
Véd: tartalom (E2E, forward secrecy), partner-hitelesítés (ujjlenyomat), partner-azonosság a vezetéken,
üzenethossz (1 KB padding), lemezes nyom (nincs napló). Tor módban az IP-k és a ki-kivel-beszél is.
Nem véd: feltört eszköz/keylogger, ujjlenyomat-egyeztetés kihagyása, a fájlok saját metaadata (EXIF, dokumentum szerző),
időzítéses elemzés erős támadó ellen, DIRECT módban az IP/forgalom metaadat.
A lemezen a fogadott fájlok, a `.partial` fájlok és (nem amnesia módban) az ismert partnerek nincsenek titkosítva.
A kulcsléptetés nem nyújt post-compromise védelmet (nincs teljes double ratchet).
**Független biztonsági audit nem történt**, érzékeny célra használat előtt érdemes elvégeztetni.

## Terminál (CLI) mód
Grafikus felület nélkül (szerveren, SSH-n):
```
python mute.py --listen --port 5555            # várakozás
python mute.py --connect 192.168.1.20:5555     # csatlakozás (több --connect is lehet)
python mute.py --tor                           # onion service Toron
python mute.py --tor --connect xyz.onion       # csatlakozás Toron át
```
Kapcsolók: `--fp <ujjlenyomat>` (elvárt partner), `--amnesia`.
Parancsok: `/send <fájl|mappa>`, `/peers`, `/fp`, `/quit`; bármi más szöveg üzenetként megy mindenkinek.

## Folytatható átvitel
Ha egy fájlküldés megszakad, a fogadó a részleges adatot megtartja (`Downloads/Mute/.partial`).
Ugyanazt a fájlt újra elküldve ott folytatódik, ahol abbamaradt (név + méret + az első 1 MiB hash-e azonosítja).
Befejezés után a részleges fájl törlődik. A fogadott fájlnevek Windows/Linux között biztonságosra tisztítva érkeznek
(tiltott karakterek `_`-ra, fenntartott nevek elé `_`).
