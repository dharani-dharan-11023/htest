#!/usr/bin/env python3
"""
Download and extract a Chrome extension by its ID or Chrome Web Store URL.

Usage:
    python3 download_extension.py <extension_id_or_url>
    python3 download_extension.py hahkojdegblcccihngmgndhdfheheofe
    python3 download_extension.py "https://chromewebstore.google.com/detail/textcortex-ai-knowledge-b/hahkojdegblcccihngmgndhdfheheofe"

The script downloads the .crx file from Google's Chrome Web Store servers,
extracts it (CRX is a ZIP with a header), and displays the extension structure.
"""

import sys
import os
import zipfile
import struct
import urllib.request
import urllib.error
import re
import shutil
import json


def extract_extension_id(input_str):
    """Extract extension ID from a Chrome Web Store URL or return as-is if already an ID."""
    # Match various Chrome Web Store URL formats
    patterns = [
        r'chromewebstore\.google\.com/detail/[^/]*/([a-z]{32})',
        r'chrome\.google\.com/webstore/detail/[^/]*/([a-z]{32})',
    ]
    for pattern in patterns:
        match = re.search(pattern, input_str)
        if match:
            return match.group(1)
    # Strip query params if present
    clean = input_str.split('?')[0].rstrip('/')
    # Check if the last path segment is an extension ID
    parts = clean.split('/')
    candidate = parts[-1] if parts else input_str
    if re.match(r'^[a-z]{32}$', candidate):
        return candidate
    # Check raw input
    if re.match(r'^[a-z]{32}$', input_str.strip()):
        return input_str.strip()
    return None


def download_crx(extension_id, output_dir):
    """Try multiple methods to download a .crx file."""
    crx_path = os.path.join(output_dir, f"{extension_id}.crx")

    # Multiple Chrome versions and URL patterns to try
    chrome_versions = ["131.0.6778.86", "120.0.6099.130", "114.0.5735.133", "49.0.2623.108"]

    download_urls = []
    for ver in chrome_versions:
        download_urls.append(
            f"https://clients2.google.com/service/update2/crx"
            f"?response=redirect&prodversion={ver}&acceptformat=crx2,crx3"
            f"&x=id%3D{extension_id}%26installsource=ondemand%26uc"
        )

    # Third-party CRX download services
    download_urls.extend([
        f"https://crxdown.com/crx/{extension_id}",
        f"https://crx-downloader.com/download/{extension_id}",
    ])

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.6778.86 Safari/537.36"
        ),
        "Accept": "*/*",
    }

    for i, url in enumerate(download_urls):
        print(f"\n[*] Attempt {i + 1}/{len(download_urls)}: {url[:80]}...")
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                data = response.read()
                if len(data) < 500:
                    print(f"[-] Response too small ({len(data)} bytes), skipping.")
                    continue
                with open(crx_path, "wb") as f:
                    f.write(data)
                print(f"[+] Downloaded {len(data):,} bytes -> {crx_path}")
                return crx_path
        except (urllib.error.HTTPError, urllib.error.URLError) as e:
            print(f"[-] Failed: {e}")
            continue

    # Try crx4chrome as fallback
    print(f"\n[*] Trying crx4chrome.com...")
    try:
        page_url = f"https://www.crx4chrome.com/crx/{extension_id}/"
        req = urllib.request.Request(page_url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as response:
            html = response.read().decode("utf-8", errors="ignore")
        links = re.findall(r'href="(https?://[^"]*\.crx[^"]*)"', html)
        for link in links:
            print(f"[*] Found CRX link: {link[:80]}...")
            req = urllib.request.Request(link, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=30) as response:
                    data = response.read()
                    if len(data) > 500:
                        with open(crx_path, "wb") as f:
                            f.write(data)
                        print(f"[+] Downloaded {len(data):,} bytes -> {crx_path}")
                        return crx_path
            except Exception as e:
                print(f"[-] Failed: {e}")
                continue
    except Exception as e:
        print(f"[-] crx4chrome failed: {e}")

    print("\n[-] All download methods failed.")
    print("[-] This usually means network restrictions are blocking the download.")
    print("[-] You can manually download the CRX file from:")
    print(f"[-]   https://crxdown.com/crx/{extension_id}")
    print(f"[-]   https://crx-downloader.com/")
    print("[-] Then run: python3 download_extension.py --extract <path_to_crx_file>")
    sys.exit(1)


def extract_crx(crx_path, output_dir):
    """Extract a .crx file (crx2 or crx3 format) to a directory."""
    with open(crx_path, "rb") as f:
        magic = f.read(4)
        if magic != b"Cr24":
            f.seek(0)
            test = f.read(2)
            if test == b"PK":
                print("[*] File is a plain ZIP (not CRX wrapped)")
                zip_offset = 0
            else:
                f.seek(0)
                data = f.read()
                pk_pos = data.find(b"PK\x03\x04")
                if pk_pos >= 0:
                    print(f"[*] Found ZIP signature at offset {pk_pos}")
                    zip_offset = pk_pos
                else:
                    print("[-] Cannot find ZIP data in file")
                    sys.exit(1)
        else:
            version = struct.unpack("<I", f.read(4))[0]
            print(f"[*] CRX version: {version}")

            if version == 2:
                pub_key_len = struct.unpack("<I", f.read(4))[0]
                sig_len = struct.unpack("<I", f.read(4))[0]
                zip_offset = 16 + pub_key_len + sig_len
            elif version == 3:
                header_size = struct.unpack("<I", f.read(4))[0]
                zip_offset = 12 + header_size
            else:
                print(f"[-] Unknown CRX version: {version}")
                sys.exit(1)

            print(f"[*] ZIP data starts at offset: {zip_offset}")

    # Derive output dir name from the CRX filename
    base_name = os.path.splitext(os.path.basename(crx_path))[0]
    extract_dir = os.path.join(output_dir, f"{base_name}_extension")
    if os.path.exists(extract_dir):
        shutil.rmtree(extract_dir)

    with open(crx_path, "rb") as f:
        f.seek(zip_offset)
        zip_data = f.read()

    zip_path = crx_path.replace(".crx", ".zip")
    with open(zip_path, "wb") as f:
        f.write(zip_data)

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(extract_dir)
        file_count = sum(len(files) for _, _, files in os.walk(extract_dir))
        print(f"[+] Extracted {file_count} files -> {extract_dir}")
    except zipfile.BadZipFile:
        print("[-] Failed to extract ZIP. File may be corrupted.")
        sys.exit(1)
    finally:
        os.remove(zip_path)

    return extract_dir


def show_structure(extract_dir):
    """Show the extracted extension structure."""
    manifest_path = os.path.join(extract_dir, "manifest.json")
    if os.path.exists(manifest_path):
        with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
            try:
                manifest = json.load(f)
                print(f"\n{'='*60}")
                print(f"Extension: {manifest.get('name', 'Unknown')}")
                print(f"Version:   {manifest.get('version', 'Unknown')}")
                print(f"Manifest:  v{manifest.get('manifest_version', '?')}")
                if 'description' in manifest:
                    desc = manifest['description'][:80]
                    print(f"Desc:      {desc}")
                if 'permissions' in manifest:
                    perms = manifest['permissions']
                    if isinstance(perms, list):
                        print(f"Permissions: {', '.join(str(p) for p in perms)}")
                print(f"{'='*60}")
            except json.JSONDecodeError:
                pass

    print(f"\n[*] Top-level contents:")
    for item in sorted(os.listdir(extract_dir)):
        full = os.path.join(extract_dir, item)
        if os.path.isdir(full):
            count = sum(len(f) for _, _, f in os.walk(full))
            print(f"    [DIR]  {item}/ ({count} files)")
        else:
            size = os.path.getsize(full)
            print(f"    [FILE] {item} ({size:,} bytes)")


def main():
    # Handle --extract mode for local CRX/ZIP files
    if len(sys.argv) >= 3 and sys.argv[1] == "--extract":
        crx_path = sys.argv[2]
        if not os.path.exists(crx_path):
            print(f"[-] File not found: {crx_path}")
            sys.exit(1)
        output_dir = os.path.dirname(os.path.abspath(crx_path))
        extract_dir = extract_crx(crx_path, output_dir)
        show_structure(extract_dir)
        print(f"\n[+] Done! Extension code is in: {extract_dir}")
        return

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 download_extension.py <extension_id_or_url>")
        print("  python3 download_extension.py --extract <path_to_crx_file>")
        print()
        print("Examples:")
        print('  python3 download_extension.py hahkojdegblcccihngmgndhdfheheofe')
        print('  python3 download_extension.py "https://chromewebstore.google.com/detail/textcortex-ai-knowledge-b/hahkojdegblcccihngmgndhdfheheofe"')
        print('  python3 download_extension.py --extract ~/Downloads/extension.crx')
        sys.exit(0)

    input_str = sys.argv[1]
    extension_id = extract_extension_id(input_str)
    if not extension_id:
        print(f"[-] Invalid extension ID or URL: {input_str}")
        sys.exit(1)

    output_dir = os.path.dirname(os.path.abspath(__file__))

    crx_path = download_crx(extension_id, output_dir)
    extract_dir = extract_crx(crx_path, output_dir)

    # Clean up .crx file
    os.remove(crx_path)

    show_structure(extract_dir)
    print(f"\n[+] Done! Extension code is in: {extract_dir}")


if __name__ == "__main__":
    main()
