"""Geração de código Pix (BR Code EMV) e QR — usado pelo provider demo.
Baseado no padrão Banco Central do Brasil (EMV QRCPS-MPM)."""
import base64
import io
import time

def _crc16(payload: str) -> str:
    pol = 0x1021
    crc = 0xFFFF
    for ch in payload + "6304":
        crc ^= ord(ch) << 8
        for _ in range(8):
            crc = ((crc << 1) ^ pol if crc & 0x8000 else crc << 1) & 0xFFFF
    return f"{crc:04X}"

def _emv(tag, value):
    return f"{tag:02d}{len(value):02d}{value}"

def build_brcode(key, amount_cents, merchant="TELEMAX", city="BRASIL", txid="TELEMAX"):
    mai = _emv(0, "BR.GOV.BCB.PIX") + _emv(1, key)
    account = _emv(26, mai)
    tx = "".join(c for c in txid if c.isalnum())[:25] or "***"
    payload = (_emv(00, "01") + _emv(26, account)
               + _emv(52, "0000") + _emv(53, "986")
               + _emv(54, f"{amount_cents/100:.2f}")
               + _emv(58, "BR") + _emv(59, merchant[:25]) + _emv(60, city[:15])
               + _emv(62, _emv(5, tx)))
    payload += "6304"
    return payload + _crc16(payload)

def qr_png_b64(brcode_text):
    import segno
    buf = io.BytesIO()
    segno.make(brcode_text, error="m").save(buf, kind="png", scale=6, border=2)
    return base64.b64encode(buf.getvalue()).decode()
