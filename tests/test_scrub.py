"""Unit tests for metadata scrubbing and Tor bridge parsing. Run: python tests/test_scrub.py
Requires Pillow (pip install pillow)."""
import os, sys, tempfile, zipfile, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import mute as m
from PIL import Image

tmp = tempfile.mkdtemp()
def ok(c, msg):
    assert c, msg
    print("PASS", msg)

# ---- JPEG: EXIF (orientation 6, make, GPS), comment, XMP
im = Image.new("RGB", (64, 48), (200, 30, 90))
for x in range(64):
    im.putpixel((x, x % 48), (0, 255, 0))
exif = Image.Exif()
exif[0x0112] = 6
exif[0x010F] = "SecretCameraMake"
exif.get_ifd(0x8825)[1] = "N"
jp = os.path.join(tmp, "p.jpg")
im.save(jp, "JPEG", exif=exif, comment=b"secretcomment", quality=90)
raw = open(jp, "rb").read()
xmp = b"http://ns.adobe.com/xap/1.0/\x00<x:xmpmeta>secretxmp</x:xmpmeta>"
raw = raw[:2] + b"\xff\xe1" + struct.pack(">H", len(xmp) + 2) + xmp + raw[2:]
open(jp, "wb").write(raw)
out = os.path.join(tmp, "p_clean.jpg")
changed, note = m.scrub_file(jp, out)
clean = open(out, "rb").read()
ok(changed, f"jpeg scrubbed: {note}")
ok(b"SecretCameraMake" not in clean and b"secretcomment" not in clean and b"secretxmp" not in clean, "no make/comment/xmp left")
ok(b"GPS" not in clean and b"Exif" in clean and len(clean) < len(raw), "only minimal EXIF (orientation) kept")
a, b = Image.open(jp), Image.open(out)
ok(b.getexif().get(0x0112) == 6 and not b.getexif().get(0x010F), "orientation preserved, make removed")
ok(list(a.convert("RGB").getdata()) == list(b.convert("RGB").getdata()), "pixels identical (no re-encode)")

# ---- PNG with text chunks
pn = os.path.join(tmp, "p.png")
from PIL import PngImagePlugin
info = PngImagePlugin.PngInfo(); info.add_text("Author", "SecretAuthor"); info.add_text("Comment", "secretpng")
im.save(pn, "PNG", pnginfo=info)
outp = os.path.join(tmp, "p_clean.png")
changed, note = m.scrub_file(pn, outp)
cp = open(outp, "rb").read()
ok(changed and b"SecretAuthor" not in cp and b"secretpng" not in cp and b"tEXt" not in cp, "png text chunks removed")
ok(list(Image.open(pn).getdata()) == list(Image.open(outp).getdata()), "png pixels identical")

# ---- DOCX (crafted)
dx = os.path.join(tmp, "d.docx")
core = (b'<?xml version="1.0"?><cp:coreProperties xmlns:cp="a" xmlns:dc="b" xmlns:dcterms="c">'
        b'<dc:creator>John Smith</dc:creator><cp:lastModifiedBy>Jane</cp:lastModifiedBy>'
        b'<dcterms:created xsi:type="dcterms:W3CDTF">2020-01-01T00:00:00Z</dcterms:created><dc:title>Plan</dc:title></cp:coreProperties>')
app = b'<Properties><Company>ACME Corp</Company><Application>Microsoft Office Word</Application><Pages>1</Pages></Properties>'
with zipfile.ZipFile(dx, "w") as z:
    z.writestr("[Content_Types].xml", b"<Types/>"); z.writestr("docProps/core.xml", core)
    z.writestr("docProps/app.xml", app); z.writestr("word/document.xml", b"<w:document>hello</w:document>")
outd = os.path.join(tmp, "d_clean.docx")
changed, note = m.scrub_file(dx, outd)
with zipfile.ZipFile(outd) as z:
    c, a_, body = z.read("docProps/core.xml"), z.read("docProps/app.xml"), z.read("word/document.xml")
    dates = {i.date_time for i in z.infolist()}
ok(b"John" not in c and b"Jane" not in c and b"2020" not in c and b"Plan" not in c, "docx core props removed")
ok(b"ACME" not in a_ and b"Microsoft" not in a_ and b"<Pages>1</Pages>" in a_, "docx app props removed, rest kept")
ok(body == b"<w:document>hello</w:document>" and dates == {(1980, 1, 1, 0, 0, 0)}, "docx body kept, timestamps zeroed")

# ---- unsupported + corrupt
open(os.path.join(tmp, "x.pdf"), "wb").write(b"%PDF-1.4")
ch, note = m.scrub_file(os.path.join(tmp, "x.pdf"), os.path.join(tmp, "o.pdf"))
ok(not ch and "not supported" in note, f"pdf reported as unsupported ({note})")
open(os.path.join(tmp, "bad.jpg"), "wb").write(b"not a jpeg")
ch, note = m.scrub_file(os.path.join(tmp, "bad.jpg"), os.path.join(tmp, "o2.jpg"))
ok(not ch and "failed" in note and not os.path.exists(os.path.join(tmp, "o2.jpg")), f"corrupt jpeg not sent half-scrubbed ({note})")

# ---- folder zip
fd = os.path.join(tmp, "proj"); os.makedirs(fd + "/sub")
import shutil; shutil.copy(jp, fd + "/sub/photo.jpg"); shutil.copy(dx, fd + "/doc.docx"); open(fd + "/notes.pdf", "wb").write(b"%PDF")
os.utime(fd + "/doc.docx", (1_000_000_000, 1_000_000_000))
zp = os.path.join(tmp, "proj.zip")
skipped = m.make_clean_zip(fd, zp, True)
with zipfile.ZipFile(zp) as z:
    names = sorted(z.namelist()); dts = {i.date_time for i in z.infolist()}
    photo = z.read("sub/photo.jpg")
ok(names == ["doc.docx", "notes.pdf", "sub/photo.jpg"], f"zip entries {names}")
ok(dts == {(1980, 1, 1, 0, 0, 0)} and b"SecretCameraMake" not in photo, "zip timestamps zeroed, photo scrubbed inside")
ok([s[0] for s in skipped] == ["notes.pdf"], f"unsupported file reported: {skipped}")

# ---- bridges
obfs = "Bridge obfs4 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=abc iat-mode=0"
b = m.parse_bridges(obfs + "\n# comment\n\nsnowflake 192.0.2.3:80 FP url=https://x\n192.0.2.9:9001 FPR")
ok([t for _, t in b] == ["obfs4", "snowflake", None] and b[0][0].startswith("obfs4 "), f"bridge parsing {[t for _, t in b]}")
try:
    m.parse_bridges("webtunnel 1.2.3.4:1 FP"); ok(False, "unsupported transport rejected")
except ValueError as e:
    ok("Unsupported" in str(e), "unsupported transport rejected")
cfg = m.build_tor_config("/tmp/d", 9050, 9051, b, {"obfs4,meek_lite": "/usr/bin/lyrebird", "snowflake": "/usr/bin/snowflake-client"})
ok(cfg["UseBridges"] == "1" and len(cfg["Bridge"]) == 3 and "obfs4,meek_lite exec /usr/bin/lyrebird" in cfg["ClientTransportPlugin"], "torrc config built")
ok("UseBridges" not in m.build_tor_config("/tmp/d", 1, 2), "no bridges -> plain config")

print("all scrub/bridge tests passed")
