"""Generate HARMLESS test fixtures into scripts/verification/.fixtures (git-ignored).

Nothing here is malware or executable code. 'Suspicious' fixtures only contain indicator
NAMES (for example /JavaScript) as text, which the static analysers look for. The PE fixture
is a header-only structure with no code or imports. Run before the verification scripts:
    python scripts/verification/make_fixtures.py
"""
import hashlib, io, os, struct, zipfile
from reportlab.pdfgen import canvas
from PIL import Image

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".fixtures")
os.makedirs(OUT, exist_ok=True)
P = lambda name: os.path.join(OUT, name)


def pe_bytes() -> bytes:
    dos = bytearray(0x80); dos[0:2] = b"MZ"; struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    opt = bytearray(0xE0); struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<I", opt, 16, 0x1000); struct.pack_into("<I", opt, 32, 0x1000)
    struct.pack_into("<I", opt, 36, 0x200); struct.pack_into("<I", opt, 60, 0x400); struct.pack_into("<I", opt, 92, 16)
    sec = bytearray(40); sec[0:6] = b".synth"
    struct.pack_into("<IIIIIIHHI", sec, 8, 0x100, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    return (bytes(dos) + b"PE\0\0" + coff + bytes(opt) + bytes(sec)).ljust(0x400, b"\0")


def docx(path, extra=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
        z.writestr("_rels/.rels", '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
        z.writestr("word/document.xml", '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Synthetic DOCX test document.</w:t></w:r></w:p></w:body></w:document>')
        if extra:
            z.writestr(*extra)
    open(path, "wb").write(buf.getvalue())


c = canvas.Canvas(P("normal.pdf")); c.drawString(72, 720, "Quarterly report - synthetic test document."); c.save()
base = open(P("normal.pdf"), "rb").read()
open(P("suspicious-indicators.pdf"), "wb").write(base + b"\n% synthetic test fixture: indicator names only\n1 0 obj << /OpenAction 2 0 R /JavaScript (app.alert('test fixture')) /Launch << /F (calc.exe) >> >> endobj\n%%EOF\n")
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("readme.txt", "synthetic archive")
    z.writestr("tools/update.exe", "harmless text, not a program")
    z.writestr("../escape.txt", "traversal name test")
open(P("archive.zip"), "wb").write(buf.getvalue())
docx(P("document.docx"))
docx(P("macro-test.docx"), ("word/vbaProject.bin", b"\x00" * 64))
Image.new("RGB", (64, 64), (40, 90, 160)).save(P("image.png"))
Image.new("RGB", (64, 64), (200, 120, 40)).save(P("image.jpg"), "JPEG")
open(P("polyglot.png"), "wb").write(open(P("image.png"), "rb").read() + b"PK\x03\x04synthetic trailing bytes")
open(P("synthetic-pe.exe"), "wb").write(pe_bytes())
open(P("mismatch-invoice.pdf"), "wb").write(pe_bytes())
open(P("malformed.pdf"), "wb").write(b"%PDF-1.4\x00\xff\xfe garbage \x00" * 5)
open(P("empty.pdf"), "wb").write(b"")
open(P("unsupported.sh"), "wb").write(b"echo synthetic\n")
with open(P("oversized.pdf"), "wb") as f:
    f.write(b"%PDF-1.4\n"); f.seek(33 * 1024 * 1024); f.write(b"%%EOF\n")
open(P("timeout-fixture.pdf"), "wb").write(b"%PDF-1.4 synthetic timeout fixture\n")
sha = lambda n: hashlib.sha256(open(P(n), "rb").read()).hexdigest()
open(P("known_sha.txt"), "w").write(sha("suspicious-indicators.pdf"))
open(P("slow_sha.txt"), "w").write(sha("timeout-fixture.pdf"))
print("fixtures written to", OUT, sorted(os.listdir(OUT)))
