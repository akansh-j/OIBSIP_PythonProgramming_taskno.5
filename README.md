# OIBSIP_PythonProgramming_taskno.

# 📡 Nexus Chat: Secure End-to-End Encrypted Messenger

**A multi-threaded, persistent chat architecture built from scratch in Python.**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)
![Tkinter](https://img.shields.io/badge/UI-Custom%20Dark%20Mode-000000?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-AES%20(Fernet)-red?style=for-the-badge)

## 📌 Project Context
This application was engineered as the **Advanced Task** for the **Oasis Infobyte Internship**.

The objective was to move beyond basic socket tutorials and build a robust **Client-Server Architecture** that handles:
1.  **Concurrency:** Multiple users chatting simultaneously without UI freezing.
2.  **Persistence:** Local SQLite storage for user credentials and history.
3.  **Security:** Payload encryption before transmission.


## 🔐 Security Implementation & Trade-offs
To differentiate this project from standard "tutorial code," specific architectural decisions were made regarding data security.

### 1. The Encryption Key Strategy
* **The Mechanism:** We utilize `cryptography.fernet` (Symmetric AES-128) to encrypt message payloads.
* **The Decision:** In a production environment, the Encryption Key would be generated via `Fernet.generate_key()` and stored in a `.env` file or a Secrets Manager. 
* **The Implementation:** For this submission, **I have manually generated a cryptographically strong 32-byte URL-safe base64 key** and pre-configured it in the source code.
    * *Why?* This ensures the application is **"Plug-and-Play"** for the evaluator. If I used a dynamic key or environment variable, the Client and Server instances might fail to handshake if not configured identically on your machine.

### 2. Payload Protection
Unlike standard socket examples that send raw `UTF-8` strings (which can be intercepted by Wireshark/packet sniffers), this application transmits **encrypted bytes**. The server routes these bytes without ever being able to read the content (End-to-End Encryption principle).

### 3. Database Safety
* **Repo Hygiene:** A `.gitignore` rule is implemented to exclude `*.db` files.
* **Reason:** This prevents accidental leakage of test credentials (
*
