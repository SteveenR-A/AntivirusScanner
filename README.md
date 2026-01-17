# 🛡️ TrueSight Scanner (Educational)

**TrueSight** is a **basic scanning engine** developed in **C# (.NET 10)** for educational purposes. Its goal is to demonstrate cybersecurity concepts such as file integrity verification and integration with threat intelligence APIs.

> [!WARNING]
> **Important Notice:** This project is an educational **Proof of Concept (PoC)**. It is **NOT a substitute for a commercial antivirus** (like Windows Defender, Kaspersky, etc.). It does not have the capability to remove active viruses from memory nor analyze internal file code (advanced heuristic analysis). Use it as a "second opinion" for suspicious files.

![Status](https://img.shields.io/badge/status-Educational-yellow) ![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-blue) ![License](https://img.shields.io/badge/license-MIT-green)

## ✨ Engine Capabilities

Unlike a traditional antivirus, TrueSight functions as a **metadata and reputation checker**:

### 1. 🔍 Static Analysis (Anti-Spoofing)
Verifies that files are what they claim to be, preventing common injection tricks:
- **Double Extension**: Detects traps like `invoice.pdf.exe`.
- **Magic Numbers**: Compares the actual file header (initial bytes) with its extension. If a file claims to be `.jpg` but its header is from an executable (`MZ`), TrueSight will block it.

### 2. ☁️ Cloud Reputation (VirusTotal)
If the file passes static analysis but is unknown:
- Calculates the **SHA-256 Hash** of the file.
- Queries the **VirusTotal** database (API Key required).
- **Free API Note**: The system automatically respects the **4 requests per minute** limit (1 every 15 sec) of free accounts to avoid blocks.
- If more than one engine in VirusTotal marks it as malicious, TrueSight will alert you.

### 3. 🛡️ Folder Monitor
- Watches a specific folder (e.g., *Downloads*) for new files.
- Intercepts newly created files for a quick scan before you open them.

## 🚀 Installation & Usage

### Requirements
- **Windows 10 or 11**.
- **.NET 10 SDK**: [Download .NET 10](https://dotnet.microsoft.com/download/dotnet/10.0).
- **VirusTotal API Key**: (Free at [virustotal.com](https://www.virustotal.com)).

### 🛠️ Compilation & Execution
This project is distributed as **Source Code** so you can study how it works.

1.  **Clone/Download**: Download the code (button `Code` -> `Download ZIP`).
2.  **Compile**:
    Open a terminal in the folder and run:
    ```powershell
    dotnet build -c Release
    dotnet run --project AntivirusScanner.csproj
    ```
3.  **Configure**:
    The application will start. Go to **Settings** and enter your API Key.

## 🧪 Testing Detection

The project includes a file named `test_threat.txt`. This file is harmless but contains a manipulated header to simulate an executable (`MZ...`).
- When attempting to scan it, TrueSight will detect that its content (looks like an EXE) does not match its extension (.txt), testing the **Anti-Spoofing** functionality.

## ⚠️ Technical Limitations
To avoid misunderstandings:
*   **No RAM scanning**: Only files on disk.
*   **No internal signature database**: Relies 100% on VirusTotal to detect known malware.
*   **Superficial scanning**: If a virus is encrypted or completely new (Zero-Day) and has correct metadata, TrueSight will not detect it until VirusTotal recognizes it.

## 🔒 Privacy
*   API Keys are stored locally.
*   Only **Hashes** (digital fingerprints) are sent to VirusTotal, never your full files.

## 🤝 Credits
Developed as a learning project on file systems and REST APIs in .NET.
Refactored with AI assistance.
