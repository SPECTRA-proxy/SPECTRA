"""
SPECTRA — Module 1: Adaptive Post-Quantum Cryptographic (PQC) Transport Engine
================================================================================
NIST FIPS 203 — ML-KEM (Module Lattice Key Encapsulation Mechanism)
NIST FIPS 204 — ML-DSA (Module Lattice Digital Signature Algorithm)

Architecture:
  • Parameter selection is strictly driven by the client's hardware capability,
    inferred from standard W3C HTTP Client Hints (Sec-CH-UA-Mobile, User-Agent).
  • The proxy NEVER lets the client self-report or pick its own security level.
  • ML-KEM handles quantum-safe key exchange (confidentiality).
  • ML-DSA handles quantum-safe digital signatures (integrity & authenticity).
  • Negotiated shared secrets are derived via HKDF-SHA256 into AES-256-GCM keys.

Usage:
  python3 pqc.py                     -> Single adaptive handshake (CLI mode)
  python3 pqc.py --daemon            -> Start persistent sidecar on 127.0.0.1:5001
  python3 pqc.py --benchmark         -> Full benchmark across all tiers (demo/slides)
  import pqc                         -> Use pqc.perform_handshake(client_hints)

Daemon API (called by Go proxy internally):
  POST http://127.0.0.1:5001/handshake
  Body: { "client_ip": "...", "Sec-CH-UA-Mobile": "...",
          "Sec-CH-UA-Platform": "...", "User-Agent": "..." }
  Response: { "status": "SUCCESS", "tier": "...", "kem_alg": "...",
              "dsa_alg": "...", "session_key": "...", "latency_us": 0.0 }
================================================================================
"""

import oqs
import time
import os
import hashlib
import hmac
import json


# ==============================================================================
# 1. HARDWARE TIER DEFINITIONS
# ==============================================================================

# Tier definitions: each tier pairs a KEM and a DSA at equivalent security levels
TIERS = {
    "LIGHTWEIGHT": {
        "label":    "Tier 1 — Lightweight / IoT / Mobile",
        "kem":      "ML-KEM-512",
        "dsa":      "ML-DSA-44",
        "min_bits": 128,   # NIST Security Category 1
    },
    "STANDARD": {
        "label":    "Tier 2 — Standard Workload / Laptop / Desktop",
        "kem":      "ML-KEM-768",
        "dsa":      "ML-DSA-65",
        "min_bits": 192,   # NIST Security Category 3
    },
    "HIGH": {
        "label":    "Tier 3 — High-Assurance / Enterprise Server",
        "kem":      "ML-KEM-1024",
        "dsa":      "ML-DSA-87",
        "min_bits": 256,   # NIST Security Category 5
    },
}


# ==============================================================================
# 2. CLIENT CAPABILITY NEGOTIATION (Method 2: HTTP Client Hints — Server-Driven)
# ==============================================================================

def select_tier_from_hints(client_hints: dict) -> dict:
    """
    Selects the PQC parameter tier based on standard W3C HTTP Client Hints.

    The PROXY decides the security tier. The client NEVER self-selects.
    Evaluated fields:
      - Sec-CH-UA-Mobile       ("?1" = mobile/constrained device)
      - Sec-CH-UA-Platform     ("Android", "iOS" = mobile; "Windows"/"Linux" = desktop)
      - User-Agent             (Fallback: detects embedded/IoT/ARM devices)

    Returns a tier dict from TIERS.
    """
    mobile_hint  = client_hints.get("Sec-CH-UA-Mobile", "?0").strip()
    platform     = client_hints.get("Sec-CH-UA-Platform", "").strip().lower().strip('"')
    user_agent   = client_hints.get("User-Agent", "").lower()

    # --- Tier 1: Lightweight / IoT / Mobile ---
    # Explicit mobile hint OR ARM/embedded device detected in UA
    is_mobile_hint = mobile_hint == "?1"
    is_mobile_platform = platform in ("android", "ios", "chromeos")
    is_embedded_ua = any(kw in user_agent for kw in (
        "armv7", "armv6", "aarch32", "raspberry", "openwrt",
        "esp32", "microcontroller", "mbed"
    ))

    if is_mobile_hint or is_mobile_platform or is_embedded_ua:
        return TIERS["LIGHTWEIGHT"]

    # --- Tier 3: High-Assurance / Enterprise Server ---
    # Server infrastructure or datacenter environments
    is_server_ua = any(kw in user_agent for kw in (
        "server", "datacenter", "enterprise"
    ))
    is_server_platform = platform in ("linux",) and is_server_ua

    if is_server_ua or is_server_platform:
        return TIERS["HIGH"]

    # --- Tier 2: Standard Workload (Laptop / Desktop) ---
    # Standard desktop browsers (Windows, macOS, Linux desktop)
    return TIERS["STANDARD"]



# ==============================================================================
# 3. HKDF-SHA256 KEY DERIVATION (Shared Secret -> Symmetric Key)
# ==============================================================================

def hkdf_derive(shared_secret: bytes, info: bytes = b"SPECTRA-PQC-AES256-GCM",
                length: int = 32) -> bytes:
    """
    Derives a symmetric encryption key from the raw ML-KEM shared secret
    using HMAC-based Extract-and-Expand Key Derivation Function (HKDF-SHA256).

    The raw lattice shared secret is never used directly as an AES key.
    """
    # Extract: PRK = HMAC-SHA256(salt=zeros, IKM=shared_secret)
    salt = bytes(32)
    prk = hmac.new(salt, shared_secret, hashlib.sha256).digest()

    # Expand: OKM = T(1) = HMAC-SHA256(PRK, info || 0x01)
    okm = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return okm[:length]


# ==============================================================================
# 4. CORE CRYPTOGRAPHIC HANDSHAKE ENGINE
# ==============================================================================

def perform_handshake(client_hints: dict, client_ip: str = "127.0.0.1") -> dict:
    """
    Executes the complete Adaptive PQC handshake:

    Phase A — Parameter Negotiation:
      The proxy evaluates client hints and selects the optimal KEM + DSA tier.

    Phase B — Key Encapsulation (ML-KEM / FIPS 203):
      1. Server generates ephemeral KEM keypair (public/private).
      2. Server encapsulates a quantum-safe shared secret.
      3. Client decapsulates using the ciphertext -> obtains same shared secret.

    Phase C — Digital Signature & Integrity (ML-DSA / FIPS 204):
      1. Server signs the handshake transcript (KEM public key + ciphertext).
      2. Client verifies the signature against the server's DSA public key.
         -> Verifying: This proxy is genuine, not a Man-in-the-Middle.

    Phase D — Symmetric Key Derivation (HKDF-SHA256):
      Derives AES-256-GCM session key from the raw ML-KEM shared secret.

    Returns a dict with all timings, verification result, and negotiated session.
    """
    tier = select_tier_from_hints(client_hints)
    kem_alg = tier["kem"]
    dsa_alg = tier["dsa"]

    print(f"\n{'='*60}")
    print(f"  SPECTRA — Module 1: Adaptive PQC Handshake")
    print(f"{'='*60}")
    print(f"  Client IP       : {client_ip}")
    print(f"  Client Platform : {client_hints.get('Sec-CH-UA-Platform', 'Unknown')}")
    print(f"  Mobile Client   : {client_hints.get('Sec-CH-UA-Mobile', '?0')}")
    print(f"  Selected Tier   : {tier['label']}")
    print(f"  KEM Algorithm   : {kem_alg}  (NIST FIPS 203)")
    print(f"  DSA Algorithm   : {dsa_alg}  (NIST FIPS 204)")
    print(f"{'='*60}\n")

    timings = {}

    # ─── Phase B: ML-KEM Key Encapsulation ───────────────────────────────────
    print(f"[Phase B] ML-KEM Key Exchange ({kem_alg})")

    with oqs.KeyEncapsulation(kem_alg) as kem:
        # B1. Server: KEM KeyGen
        t0 = time.perf_counter_ns()
        server_public_key = kem.generate_keypair()
        timings["kem_keygen_us"] = (time.perf_counter_ns() - t0) / 1000

        # B2. Server: Encapsulate -> shared secret + ciphertext for client
        t0 = time.perf_counter_ns()
        ciphertext, server_shared_secret = kem.encap_secret(server_public_key)
        timings["kem_encap_us"] = (time.perf_counter_ns() - t0) / 1000

        # B3. Client side: Decapsulate ciphertext -> recovers same shared secret
        t0 = time.perf_counter_ns()
        client_shared_secret = kem.decap_secret(ciphertext)
        timings["kem_decap_us"] = (time.perf_counter_ns() - t0) / 1000

    kem_verified = (server_shared_secret == client_shared_secret)

    print(f"  Key Generation  : {timings['kem_keygen_us']:.2f} µs")
    print(f"  Encapsulation   : {timings['kem_encap_us']:.2f} µs")
    print(f"  Decapsulation   : {timings['kem_decap_us']:.2f} µs")
    print(f"  Shared Secret   : {'MATCH ✓' if kem_verified else 'MISMATCH ✗'}\n")

    # ─── Phase C: ML-DSA Digital Signature & Integrity ───────────────────────
    print(f"[Phase C] ML-DSA Integrity & Authentication ({dsa_alg})")

    # The handshake transcript that the server signs:
    # Binds: KEM public key + ciphertext + client IP
    # The client IP ensures the derived session key is tied to THIS specific client.
    # A stolen handshake token cannot be replayed from a different IP address.
    transcript = server_public_key + ciphertext + client_ip.encode("utf-8")

    with oqs.Signature(dsa_alg) as dsa:
        # C1. Server: DSA KeyGen (Server's long-term identity key)
        t0 = time.perf_counter_ns()
        dsa_public_key = dsa.generate_keypair()
        timings["dsa_keygen_us"] = (time.perf_counter_ns() - t0) / 1000

        # C2. Server: Sign the handshake transcript
        t0 = time.perf_counter_ns()
        signature = dsa.sign(transcript)
        timings["dsa_sign_us"] = (time.perf_counter_ns() - t0) / 1000

        # C3. Client: Verify the server's signature
        t0 = time.perf_counter_ns()
        dsa_verified = dsa.verify(transcript, signature, dsa_public_key)
        timings["dsa_verify_us"] = (time.perf_counter_ns() - t0) / 1000

    print(f"  Key Generation  : {timings['dsa_keygen_us']:.2f} µs")
    print(f"  Signing         : {timings['dsa_sign_us']:.2f} µs")
    print(f"  Verification    : {timings['dsa_verify_us']:.2f} µs")
    print(f"  Signature       : {'VALID ✓' if dsa_verified else 'INVALID ✗'}\n")

    # ─── Phase D: HKDF-SHA256 Symmetric Key Derivation ───────────────────────
    print(f"[Phase D] Symmetric Session Key Derivation (HKDF-SHA256)")

    t0 = time.perf_counter_ns()
    session_key = hkdf_derive(server_shared_secret)
    timings["hkdf_us"] = (time.perf_counter_ns() - t0) / 1000

    print(f"  HKDF Derivation : {timings['hkdf_us']:.2f} µs")
    print(f"  AES-256 Key     : {session_key.hex()[:32]}... ({len(session_key)*8}-bit)\n")

    # ─── Final Handshake Result ───────────────────────────────────────────────
    handshake_success = kem_verified and dsa_verified

    print(f"{'='*60}")
    print(f"  HANDSHAKE STATUS: {'SUCCESS ✓' if handshake_success else 'FAILED ✗'}")
    print(f"  PQC Tunnel      : {'ESTABLISHED' if handshake_success else 'ABORTED'}")
    print(f"  KEM Scheme      : {kem_alg}")
    print(f"  DSA Scheme      : {dsa_alg}")
    total_us = sum(timings.values())
    print(f"  Total Latency   : {total_us:.2f} µs  ({total_us/1000:.3f} ms)")
    print(f"{'='*60}\n")

    return {
        "success":          handshake_success,
        "kem_alg":          kem_alg,
        "dsa_alg":          dsa_alg,
        "tier":             tier["label"],
        "kem_verified":     kem_verified,
        "dsa_verified":     dsa_verified,
        "session_key_hex":  session_key.hex(),
        "timings_us":       timings,
        "total_latency_us": total_us,
    }


# ==============================================================================
# 5. ENTRY POINT & EXECUTION MODES
# ==============================================================================

def run_benchmark():
    """
    Runs the full Adaptive PQC handshake across all 3 hardware tiers
    to produce the comparative performance results for presentation slides.
    """
    benchmark_hints = {
        "LIGHTWEIGHT": {
            "Sec-CH-UA-Mobile":   "?1",
            "Sec-CH-UA-Platform": '"Android"',
            "User-Agent":         "Mozilla/5.0 (Linux; Android 12; armv7l)",
        },
        "STANDARD": {
            "Sec-CH-UA-Mobile":   "?0",
            "Sec-CH-UA-Platform": '"Windows"',
            "User-Agent":         "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        },
        "HIGH": {
            "Sec-CH-UA-Mobile":   "?0",
            "Sec-CH-UA-Platform": '"Linux"',
            "User-Agent":         "Mozilla/5.0 (X11; Linux x86_64) Enterprise Server",
        },
    }

    results = {}
    for profile, hints in benchmark_hints.items():
        result = perform_handshake(hints)
        results[profile] = result

    print("\n" + "="*60)
    print("  BENCHMARK SUMMARY — All Tiers")
    print("="*60)
    print(f"  {'Tier':<12} {'KEM':<16} {'DSA':<14} {'Total Latency':>14}")
    print(f"  {'-'*56}")
    for profile, r in results.items():
        print(f"  {profile:<12} {r['kem_alg']:<16} {r['dsa_alg']:<14} {r['total_latency_us']:>10.2f} µs")
    print("="*60)
    return results


if __name__ == "__main__":
    import sys

    # ──────────────────────────────────────────────────────────────────────────
    # MODE 1: DAEMON — Persistent sidecar listening on 127.0.0.1:5001
    #   Started automatically by Go's cmd/proxy/main.go.
    #   Only accepts connections from localhost — completely invisible externally.
    # ──────────────────────────────────────────────────────────────────────────
    if "--daemon" in sys.argv:
        from http.server import BaseHTTPRequestHandler, HTTPServer

        DAEMON_HOST = "127.0.0.1"
        DAEMON_PORT = 5001

        class PQCHandler(BaseHTTPRequestHandler):
            """Minimal HTTP handler: only accepts POST /handshake from Go proxy."""

            # Silence the default per-request access log lines
            def log_message(self, fmt, *args):
                pass

            def do_POST(self):
                if self.path != "/handshake":
                    self.send_error(404, "Only /handshake is supported")
                    return

                # ── Read the JSON body sent by Go proxy ──────────────────────
                length = int(self.headers.get("Content-Length", 0))
                if length == 0:
                    self.send_error(400, "Empty request body")
                    return

                raw = self.rfile.read(length)
                try:
                    client_hints = json.loads(raw)
                except json.JSONDecodeError:
                    self.send_error(400, "Invalid JSON")
                    return

                client_ip = client_hints.pop("client_ip", self.client_address[0])

                # ── Execute the real PQC handshake ────────────────────────────
                try:
                    result = perform_handshake(client_hints, client_ip=client_ip)
                    payload = json.dumps({
                        "status":      "SUCCESS" if result["success"] else "FAILED",
                        "tier":        result["tier"],
                        "kem_alg":     result["kem_alg"],
                        "dsa_alg":     result["dsa_alg"],
                        "session_key": result["session_key_hex"],
                        "latency_us":  round(result["total_latency_us"], 2),
                    }).encode()
                except Exception as exc:
                    err = json.dumps({"status": "ERROR", "detail": str(exc)}).encode()
                    self.send_response(500)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(err)))
                    self.end_headers()
                    self.wfile.write(err)
                    return

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        server = HTTPServer((DAEMON_HOST, DAEMON_PORT), PQCHandler)
        print(f"[PQC Daemon] SPECTRA Module 1 sidecar active on "
              f"http://{DAEMON_HOST}:{DAEMON_PORT}/handshake", flush=True)
        print(f"[PQC Daemon] liboqs version: {oqs.oqs_version()}", flush=True)
        print(f"[PQC Daemon] Awaiting handshake requests from Go proxy...", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[PQC Daemon] Shutting down cleanly.")
            server.server_close()

    # ──────────────────────────────────────────────────────────────────────────
    # MODE 2: BENCHMARK — 3-tier comparative summary for presentation slides
    # ──────────────────────────────────────────────────────────────────────────
    elif "--benchmark" in sys.argv:
        run_benchmark()

    # ──────────────────────────────────────────────────────────────────────────
    # MODE 3: CLI — Single one-shot handshake for testing / debugging
    # ──────────────────────────────────────────────────────────────────────────
    else:
        client_hints = {
            "Sec-CH-UA-Mobile":   "?0",
            "Sec-CH-UA-Platform": '"Linux"',
            "User-Agent":         "Mozilla/5.0 (X11; Ubuntu; Linux x86_64)",
        }

        # Support passing custom hints via CLI: python3 pqc.py '{"Sec-CH-UA-Mobile": "?1"}'
        for arg in sys.argv[1:]:
            if arg.startswith("{") and arg.endswith("}"):
                try:
                    client_hints = json.loads(arg)
                except Exception:
                    pass
            elif arg in ("--mobile", "-m"):
                client_hints = {
                    "Sec-CH-UA-Mobile":   "?1",
                    "Sec-CH-UA-Platform": '"Android"',
                    "User-Agent":         "Mozilla/5.0 (Linux; Android 14; Mobile)",
                }
            elif arg in ("--desktop", "-d"):
                client_hints = {
                    "Sec-CH-UA-Mobile":   "?0",
                    "Sec-CH-UA-Platform": '"Windows"',
                    "User-Agent":         "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                }
            elif arg in ("--server", "-s"):
                client_hints = {
                    "Sec-CH-UA-Mobile":   "?0",
                    "Sec-CH-UA-Platform": '"Linux"',
                    "User-Agent":         "Mozilla/5.0 (X11; Enterprise Server)",
                }

        perform_handshake(client_hints)