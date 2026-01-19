# 🛡️ TrueSight Scanner (Educational)

**TrueSight** is a **basic scanning engine** developed in **C# (.NET 8)** for educational purposes. Its goal is to demonstrate cybersecurity concepts such as file integrity verification and integration with threat intelligence APIs.

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
- **Smart Filtering (Democracy & VIP Rules)**:
    - **Democracy Rule**: Requires at least **4 engines** to confirm a threat before blocking.
    - **VIP Club**: If a major vendor (**Microsoft, Kaspersky, Google, ESET, BitDefender, Symantec**) detects it, it is treated as a confirmed threat immediately.

### 3. 🛡️ Folder Monitor
- Watches a specific folder (e.g., *Downloads*) for new files.
- Intercepts newly created files for a quick scan before you open them.

## 🚀 Installation & Usage

### Requirements
- **Windows 10 or 11**.
- **.NET Desktop Runtime 8.0**: [Download Here](https://dotnet.microsoft.com/en-us/download/dotnet/8.0).
- **VirusTotal API Key**: (Free at [virustotal.com](https://www.virustotal.com)).

### 🛠️ Compilation & Execution
This project is distributed as **Source Code** for educational study.

1.  **Clone/Download**: Download the code (button `Code` -> `Download ZIP`).
2.  **Compile**:
    Open a terminal in the folder and run:
    ```powershell
    dotnet publish -c Release -r win-x64 --self-contained false
    ```
    *The executable will be in `bin/Release/net8.0-windows/win-x64/publish`.*
3.  **Run**:
    Open the generated `TrueSight.exe`.
4.  **Configure**:
    The application will start. Go to **Settings** and enter your API Key.

## 🧪 Testing Detection

The project includes a file named `test_threat.txt`. This file is harmless but contains a manipulated header to simulate an executable (`MZ...`).
- When attempting to scan it, TrueSight will detect that its content (looks like an EXE) does not match its extension (.txt), testing the **Anti-Spoofing** functionality.

## ⚠️ Limitations & Best Practices

To ensure transparency and manage expectations:

### 1. VirusTotal & False Positives
You may notice some generic detections (e.g., *Generic.ML*, *Heuristic*, *Suspicious*) when scanning the `TrueSight.exe` itself. This is expected:
*   **Paranoid Engines**: Cloud engines are often set to maximum sensitivity.
*   **AI False Positives**: Engines like *SecureAge APEX* often flag unknown, unsigned executables that perform system operations (like hashing or moving files) as suspicious.
*   **Consensus Matters**: TrueSight uses "Democracy" and "VIP" rules to filter these out in its own scans, but VirusTotal's raw report shows everything. If major vendors (Microsoft, Google, etc.) show "Clean", ignore the noise.

### 2. Offline Mode Limitations
TrueSight is a **Hybrid Detection System**. Without internet:
*   **No Cloud Check**: Hash validation against VirusTotal is impossible.
*   **Reduced Protection**: Reliance shifts entirely to basic local heuristics. Modern malware will likely be missed.
*   **Action**: Always use with an active internet connection for the "Second Opinion" to work.

### 3. Technical Scope
*   **No RAM Scanning**: Scans files on disk only.
*   **No Heuristic Deep Analysis**: Relies on metadata and reputation, not code emulation.

## 🔒 Privacy
*   **Local Storage**: API Keys are stored locally on your machine.
*   **Hash-Only**: Only file **Hashes** (digital fingerprints) are sent to VirusTotal. Your actual files are never uploaded.

## 🤝 Credits
Developed as an educational project on file systems, REST APIs, and C# Security concepts.
Refactored with AI assistance.

## 🗑️ Uninstall & Cleanup
Since this is a portable application (no installer):

1.  **Delete Files**: Remove the folder where you compiled/downloaded the code.
2.  **Remove Saved Data**: Delete the `%AppData%\TrueSight` folder.
3.  **Remove Startup**: If enabled, disable "TrueSight" in Task Manager > Startup.
