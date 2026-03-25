"""
Test to verify Chrome extension can be downloaded via proxy-listed domains.

Proxy domains tested:
  - clients2.google.com
  - clients2.googleusercontent.com
  - chromewebstore.google.com
  - dl.google.com
  - redirector.gvt1.com
  - edgedl.me.gvt1.com
"""

import unittest
import urllib.request
import urllib.error
import ssl

EXTENSION_ID = "eanggfilgoajaocelnaflolkadkeghjp"

# Timeout for each HTTP request (seconds)
REQUEST_TIMEOUT = 30


def _build_opener():
    """Build a URL opener with TLS and redirect support."""
    ctx = ssl.create_default_context()
    https_handler = urllib.request.HTTPSHandler(context=ctx)
    return urllib.request.build_opener(https_handler)


def _get(url, method="GET"):
    """Make an HTTP request and return (status_code, final_url, headers, body_bytes).

    Raises urllib.error.HTTPError for HTTP error responses.
    Raises urllib.error.URLError for network/proxy/tunnel failures.
    """
    opener = _build_opener()
    req = urllib.request.Request(url, method=method)
    req.add_header(
        "User-Agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36",
    )
    resp = opener.open(req, timeout=REQUEST_TIMEOUT)
    body = resp.read(512)  # read only first 512 bytes for header checks
    return resp.getcode(), resp.geturl(), resp.headers, body


class TestChromeExtensionDownloadDomains(unittest.TestCase):
    """Verify that each proxy-listed domain is reachable and the CRX can be downloaded."""

    # ----------------------------------------------------------------
    # 1. chromewebstore.google.com — extension listing page
    # ----------------------------------------------------------------
    def test_chromewebstore_listing_reachable(self):
        """Chrome Web Store detail page returns HTTP 200."""
        url = f"https://chromewebstore.google.com/detail/{EXTENSION_ID}"
        status, final_url, _, _ = _get(url)
        self.assertEqual(status, 200, f"Expected 200, got {status}")
        print(f"\n  Chrome Web Store listing OK (200) — {final_url}")

    # ----------------------------------------------------------------
    # 2. clients2.google.com — CRX update/redirect endpoint
    # ----------------------------------------------------------------
    def test_clients2_google_update_redirect(self):
        """Update-check on clients2.google.com redirects to a CRX download."""
        url = (
            "https://clients2.google.com/service/update2/crx"
            "?response=redirect&os=win&arch=x64&os_arch=x86_64"
            "&nacl_arch=x86-64&prod=chromecrx&prodchannel=unknown"
            "&prodversion=124.0.0.0&acceptformat=crx2,crx3"
            f"&x=id%3D{EXTENSION_ID}%26uc"
        )
        status, final_url, _, body = _get(url)
        self.assertEqual(status, 200, f"CRX redirect chain failed with {status}")
        # After redirect chain, final URL should be on googleusercontent.com
        self.assertIn("googleusercontent.com", final_url,
                       "Expected redirect to land on googleusercontent.com")
        print(f"\n  clients2.google.com redirect OK → {final_url}")

    # ----------------------------------------------------------------
    # 3. clients2.googleusercontent.com — CRX blob hosting
    # ----------------------------------------------------------------
    def test_clients2_googleusercontent_serves_crx(self):
        """CRX download from clients2.googleusercontent.com has valid CRX header."""
        url = (
            "https://clients2.google.com/service/update2/crx"
            "?response=redirect&os=win&arch=x64&os_arch=x86_64"
            "&nacl_arch=x86-64&prod=chromecrx&prodchannel=unknown"
            "&prodversion=124.0.0.0&acceptformat=crx2,crx3"
            f"&x=id%3D{EXTENSION_ID}%26uc"
        )
        status, final_url, headers, body = _get(url)
        self.assertEqual(status, 200)
        self.assertIn("clients2.googleusercontent.com", final_url,
                       "Download did not resolve to clients2.googleusercontent.com")
        # CRX3 magic bytes = "Cr24"
        self.assertTrue(
            body[:4] in (b"Cr24", b"Cr22"),
            f"Not a valid CRX file. First 4 bytes: {body[:4]!r}",
        )
        print(f"\n  clients2.googleusercontent.com served valid CRX (magic: {body[:4]!r})")

    # ----------------------------------------------------------------
    # 4. dl.google.com — reachability check
    # ----------------------------------------------------------------
    def test_dl_google_reachable(self):
        """dl.google.com responds over HTTPS."""
        url = "https://dl.google.com/"
        try:
            status, _, _, _ = _get(url)
            print(f"\n  dl.google.com reachable (HTTP {status})")
        except urllib.error.HTTPError as e:
            # Any HTTP error response means the domain is reachable
            print(f"\n  dl.google.com reachable (HTTP {e.code})")
        except urllib.error.URLError as e:
            if "403 Forbidden" in str(e):
                self.fail(
                    "dl.google.com blocked by proxy (Tunnel 403 Forbidden). "
                    "Ensure dl.google.com is added to the proxy allowlist."
                )
            else:
                self.fail(f"dl.google.com unreachable: {e}")

    # ----------------------------------------------------------------
    # 5. redirector.gvt1.com — reachability check
    # ----------------------------------------------------------------
    def test_redirector_gvt1_reachable(self):
        """redirector.gvt1.com responds over HTTPS."""
        url = "https://redirector.gvt1.com/"
        try:
            status, _, _, _ = _get(url)
            print(f"\n  redirector.gvt1.com reachable (HTTP {status})")
        except urllib.error.HTTPError as e:
            print(f"\n  redirector.gvt1.com reachable (HTTP {e.code})")
        except urllib.error.URLError as e:
            if "403 Forbidden" in str(e):
                self.fail(
                    "redirector.gvt1.com blocked by proxy (Tunnel 403 Forbidden). "
                    "Ensure redirector.gvt1.com is added to the proxy allowlist."
                )
            else:
                self.fail(f"redirector.gvt1.com unreachable: {e}")

    # ----------------------------------------------------------------
    # 6. edgedl.me.gvt1.com — reachability check
    # ----------------------------------------------------------------
    def test_edgedl_me_gvt1_reachable(self):
        """edgedl.me.gvt1.com responds over HTTPS."""
        url = "https://edgedl.me.gvt1.com/"
        try:
            status, _, _, _ = _get(url)
            print(f"\n  edgedl.me.gvt1.com reachable (HTTP {status})")
        except urllib.error.HTTPError as e:
            print(f"\n  edgedl.me.gvt1.com reachable (HTTP {e.code})")
        except urllib.error.URLError as e:
            if "403 Forbidden" in str(e):
                self.fail(
                    "edgedl.me.gvt1.com blocked by proxy (Tunnel 403 Forbidden). "
                    "Ensure edgedl.me.gvt1.com is added to the proxy allowlist."
                )
            else:
                self.fail(f"edgedl.me.gvt1.com unreachable: {e}")

    # ----------------------------------------------------------------
    # End-to-end: full CRX download with size validation
    # ----------------------------------------------------------------
    def test_full_crx_download_end_to_end(self):
        """Full CRX download succeeds with valid magic header and non-trivial size."""
        url = (
            "https://clients2.google.com/service/update2/crx"
            "?response=redirect&os=win&arch=x64&os_arch=x86_64"
            "&nacl_arch=x86-64&prod=chromecrx&prodchannel=unknown"
            "&prodversion=124.0.0.0&acceptformat=crx2,crx3"
            f"&x=id%3D{EXTENSION_ID}%26uc"
        )
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url)
        req.add_header(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36",
        )
        resp = urllib.request.urlopen(req, timeout=60, context=ctx)
        data = resp.read()
        final_url = resp.geturl()
        resp.close()

        # Validate CRX magic header
        self.assertIn(data[:4], (b"Cr24", b"Cr22"),
                       f"Invalid CRX magic: {data[:4]!r}")

        # CRX should be at least 100KB for a real extension
        size_kb = len(data) / 1024
        self.assertGreater(size_kb, 100,
                           f"CRX file too small ({size_kb:.1f} KB) — likely not a real extension")

        print(f"\n  Full CRX download: {size_kb:.0f} KB, magic={data[:4]!r}")
        print(f"  Final URL: {final_url}")
        print(f"  Redirect chain: clients2.google.com → clients2.googleusercontent.com")


if __name__ == "__main__":
    unittest.main(verbosity=2)
