# Mute

Szerver nélküli, végpontok közötti titkosított chat, fájl- és mappaküldés. Windows + Linux.

## Futtatás
```
pip install -r requirements.txt
python mute.py          # Linuxon: sudo apt install python3-tk
```
Windows .exe: `build_windows.bat` → `dist\Mute.exe`

## Hálózati módok
- **DIRECT**: IP:port (LAN, port forward, vagy bármilyen VPN – Tailscale/ZeroTier/WireGuard – IP-je).
- **TOR**: nincs port forward, NAT-on át megy, az IP-d nem látszik. Az app ideiglenes `.onion` címet generál
  (minden indításnál új). Ehhez kell a `tor`:
  - Windows: Tor Expert Bundle `tor.exe` → az app mellé a `tor\` mappába (vagy Tor Browser telepítve)
  - Linux: `sudo apt install tor`
  Tor módban a kimenő kapcsolatok is Toron mennek (a partner sem látja az IP-det).

## Használat
1. Indítás → jelszó az identitáskulcshoz (üres = nincs).
2. Mód kiválasztása → **START**. A címedet (IP vagy .onion) és az ujjlenyomatodat add át a partnernek biztonságos csatornán.
3. A másik fél beírja a címedet → **CONNECT**. Első alkalommal ellenőrzitek az ujjlenyomatot.
4. Csoport: több partnerhez is csatlakozhatsz; az üzenet/fájl mindenkinek megy, akihez kapcsolódsz (teljes háló, nincs továbbítás: A–B és A–C kapcsolatnál B és C nem lát egymást).
5. Nagy fájl: 256 KB-os darabok, sebesség/ETA. Mappa: automatikusan zip. Fogadás: `Downloads/Mute`.
6. **wipe**: chat törlése. **PANIC**: chat törlés + kapcsolatok bontása + kilépés. **amnesia**: nem ment ismert partnereket.

## Mit véd és mit nem
Véd: tartalom (E2E, forward secrecy), partner-hitelesítés (ujjlenyomat), üzenethossz (1 KB padding),
lemezes nyom (nincs napló). Tor módban az IP-k és a ki-kivel-beszél is.
Nem véd: feltört eszköz/keylogger, ujjlenyomat-egyeztetés kihagyása, a fájlok saját metaadata (EXIF, dokumentum szerző),
időzítéses elemzés erős támadó ellen, DIRECT módban az IP/forgalom metaadat.
Nincs fájlküldés-folytatás: megszakadt átvitelt elölről kell indítani.
