# TLS Handshake Checker

A lightweight Python tool for analyzing TLS/SSL handshakes — including protocol versions, ciphers, ALPN negotiation, and certificate details — without external dependencies.

---

## Overview

When you visit a website over HTTPS, your browser and the server negotiate:

- **TLS version** (e.g., TLS 1.3, TLS 1.2)
- **Cipher suite** (e.g., AES-GCM, CHACHA20-POLY1305)
- **ALPN protocol** (`h2`, `http/1.1`, etc.)
- **X.509 certificate** information (subject, issuer, SANs, expiry)

This script connects directly to a target host and prints a clear summary of the negotiated handshake parameters.  
It’s ideal for quick security assessments, debugging HTTPS endpoints, or demonstrating TLS negotiation behavior.

---

## Features

- Detects **supported TLS versions** (TLS 1.0 – TLS 1.3)
- Displays **negotiated version**, **cipher**, and **ALPN**
- Extracts and parses **certificate details**
- Works entirely via Python’s standard library (`ssl`, `socket`)
- Optional **verbose JSON output** for scripting or CI integration

---

## Quick Start

```bash
# Python 3.10+ recommended
python3 tls_probe.py example.com 443

# Verbose JSON output
python3 tls_probe.py example.com 443 -v
