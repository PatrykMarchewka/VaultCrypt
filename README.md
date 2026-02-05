# <img src="Properties/VaultCryptLogo.ico" style="height: 1em;"> VaultCrypt
VaultCrypt is a desktop application allowing you to encrypt and store multiple files inside a single portable vault.

## Table of contents

- [Tech stack](#tech-stack)
- [Features](#features)
- [Requirements](#requirements)
- [Technical notes](#technical-notes)
- [Releases](#releases)

## Tech Stack
- **C# 12**
- **.NET Core 8.0 LTS**
- **Windows Presentation Foundation (WPF)**
- **MVVM Architecture**

## Features
- Create encrypted portable vault files `.vlt` to store sensitive files.
- Vault automatically resizes when possible
    - If deleted file is the last entry, the vault shrinks
    - Otherwise the block is securely wiped by zeroing
- Trimming function included to recreate the entire vault without zeroed blocks and broken metadata
- Add or remove files through a clean and easy to use interface.
- Files are split into **1–2048 MB** chunks, each encrypted independently.
- Clean and intuitive WPF interface.

## Requirements
- Windows 10 (64-bit) or later

## Technical Notes
- Supported encryption algorithms:
    - AES-GCM 128/192/256 **(AES-256-GCM used for vault metadata)**
    - AES-CCM 128/192/256
    - AES-EAX 128/192/256
    - ChaCha20-Poly1305
    - Twofish-CTR 128/192/256
- Each vault can contain up to **512 files**
- Vaults use a custom format `.vlt`

## Releases
Latest release available at [GitHub releases page](https://github.com/PatrykMarchewka/VaultCrypt/releases)

# Licenses
VaultCrypt is licensed under [MIT](LICENSE)  
This project includes third‑party components. Their licenses are listed in the [THIRD‑PARTY‑NOTICES](THIRD-PARTY-NOTICES.txt) file.
