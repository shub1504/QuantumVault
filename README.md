# 🔐 QuantumVault

### Quantum-Safe Credential Vault for Post-Breach Cryptographic Hardening

<p align="center">
  <b>Future-proof your credentials against quantum threats</b><br>
  Post-quantum encryption • Breach detection • Automated hardening
</p>

---

<div align="center">

# Quantum-Safe Credential Vault (QSCV)

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Post-Quantum](https://img.shields.io/badge/Cryptography-Post--Quantum-green?style=for-the-badge)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![Kyber-768](https://img.shields.io/badge/Algorithm-Kyber--768-orange?style=for-the-badge)](https://pq-crystals.org/kyber/)
[![AES-256-GCM](https://img.shields.io/badge/Encryption-AES--256--GCM-red?style=for-the-badge)](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![SQLite](https://img.shields.io/badge/SQLite-07405E?style=for-the-badge&logo=sqlite&logoColor=white)](https://www.sqlite.org/)

**Secure your secrets for the quantum era.**  
*CryptoVault uses post-quantum encryption and zero-knowledge design to keep your credentials safe—even after a breach.*

</div>

---

## 🚨 The Problem

Traditional encryption systems such as **RSA** and **ECC** may become vulnerable in the era of quantum computing. Attackers can steal encrypted credentials today and decrypt them later using quantum algorithms.

This is known as:

> **Harvest Now, Decrypt Later**

Without quantum-safe protection, sensitive credentials could become exposed in the future.

---

## 💡 The Solution

**QuantumVault** is a post-breach cryptographic hardening system that:

* Detects compromised credentials
* Re-encrypts them using post-quantum cryptography
* Stores them in a secure vault
* Protects against future quantum attacks

---

## ✨ Key Features

🔐 **Post-Quantum Encryption**
Uses quantum-resistant algorithms such as Kyber.

🛡️ **Breach Detection Engine**
Identifies compromised or weak credentials.

⚙️ **Automated Cryptographic Hardening**
Replaces weak encryption with quantum-safe methods.

🏦 **Secure Credential Vault**
Stores credentials in encrypted, protected form.

🧩 **Modular Architecture**
Easy to extend and integrate into other systems.

---

## 🏗️ System Architecture

```QSCV/
User Credentials
        │
        ▼
Credential Input Module
        │
        ▼
Breach Detection Engine
        │
        ▼
Post-Quantum Encryption Layer
        │
        ▼
QuantumVault Secure Storage
```

---

## 📁 Project Structure

```
QSCV/
├── backend/
│   ├── app.py
│   ├── requirments.txt      <-- Note the typo in filename
│   └── vault_Core.py        <-- Contains most crypto logic
├── frontend/
│   ├── index.html
│   ├── logo.svg
│   ├── script.js
│   └── style.css
├── main.py                  <-- FastAPI entry point (in root)
├── README.md
├── demo_vault.db
├── qscv.db
└── vault_v2.db
```

---

## 🚀 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/shub1504/QuantumVault.git
cd QuantumVault
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

Activate it:

**Windows**

```bash
venv\Scripts\activate
```

**Linux / Mac**

```bash
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the project

```bash
python main.py
```

---

## 🔄 Example Workflow

```
Input: user@example.com / password123

Step 1: Breach detected
Step 2: Weak encryption found
Step 3: Re-encrypted using Kyber
Step 4: Stored in QuantumVault
```

---

## 🎯 Use Cases

* Password managers
* Enterprise credential vaults
* Post-breach remediation tools
* Zero-trust authentication systems
* Government and defense data protection

---

## ⭐ Unique Selling Points

* Quantum-safe credential protection
* Automatic post-breach hardening
* Future-proof encryption
* Lightweight and modular design

---

## 🔮 Future Scope

* Real-time breach intelligence integration
* Multi-factor quantum-safe authentication
* Hardware-backed secure vault (TPM/SGX)
* Cloud-native deployment

---
## References

1. Bos, J., Ducas, L., Kiltz, E., et al.  
   *CRYSTALS-Kyber: A CCA-secure module-lattice-based KEM*  
   IEEE European Symposium on Security and Privacy, 2018.

2. National Institute of Standards and Technology (NIST).  
   *Post-Quantum Cryptography Standards (FIPS 203–205)*  
   2024.

3. Mosca, M.  
   *Cybersecurity in an Era with Quantum Computers: Will We Be Ready?*  
   IEEE Security & Privacy, 2018.


