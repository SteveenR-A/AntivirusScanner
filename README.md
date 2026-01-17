# 🛡️ TrueSight Scanner (Educational)

**TrueSight** es un **motor de escaneo básico** desarrollado en **C# (.NET 10)** con fines educativos. Su objetivo es demostrar conceptos de seguridad informática como la verificación de integridad de archivos y la integración con APIs de inteligencia de amenazas.

> [!WARNING]
> **Aviso Importante:** Este proyecto es una **Prueba de Concepto (PoC)** educativa. **NO es un sustituto de un antivirus comercial** (como Windows Defender, Kaspersky, etc.). No tiene capacidad de eliminar virus activos en memoria ni analizar el código interno de los archivos (análisis heurístico avanzado). Úsalo como una "segunda opinión" para archivos sospechosos.

![Status](https://img.shields.io/badge/status-Educational-yellow) ![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-blue) ![License](https://img.shields.io/badge/license-MIT-green)

## ✨ Capacidades del Motor

A diferencia de un antivirus tradicional, TrueSight funciona como un **verificador de metadatos y reputación**:

### 1. � Análisis Estático (Anti-Spoofing)
Verifica que los archivos sean lo que dicen ser, previniendo trucos comunes de inyección:
- **Doble Extensión**: Detecta trampas como `factura.pdf.exe`.
- **Magic Numbers**: Compara la cabecera real del archivo (bytes iniciales) con su extensión. Si un archivo dice ser `.jpg` pero su cabecera es de un ejecutable (`MZ`), TrueSight lo bloqueará.

### 2. ☁️ Reputación en la Nube (VirusTotal)
Si el archivo pasa el análisis estático pero es desconocido:
- Calcula el **Hash SHA-256** del archivo.
- Consulta la base de datos de **VirusTotal** (requiere API Key).
- Si más de un motor en VirusTotal lo marca como malicioso, TrueSight te alertará.

### 3. �️ Monitor de Carpetas
- Vigila una carpeta específica (ej. *Descargas*) en busca de nuevos archivos.
- Intercepta archivos recién creados para un análisis rápido antes de que los abras.

## 🚀 Instalación y Uso

### Requisitos
- **Windows 10 o 11**.
- **.NET 10 Runtime** (o usar versión autocontenida).
- **API Key de VirusTotal**: Necesaria para la funcionalidad de detección de malware real. (Gratuita en [virustotal.com](https://www.virustotal.com)).

### Ejecución
1.  Compila o descarga la aplicación.
2.  Ejecuta `AntivirusScanner.exe`.
3.  Ve a **Configuración** e introduce tu API Key.
4.  Activa el monitor para vigilar tu carpeta de descargas.

## 🧪 Probando la Detección

El proyecto incluye un archivo `test_threat.txt`. Este archivo es inofensivo pero tiene una cabecera manipulada para simular un ejecutable (`MZ...`).
- Al intentar escanearlo, TrueSight detectará que su contenido (parece EXE) no coincide con su extensión (.txt), probando la funcionalidad de **Anti-Spoofing**.

## ⚠️ Limitaciones Técnicas
Para evitar malentendidos (y "funas"):
*   **No escanea memoria RAM**: Solo archivos en disco.
*   **No tiene base de firmas propia**: Depende 100% de VirusTotal para detectar malware conocido.
*   **Escaneo superficial**: Si un virus está encriptado o es completamente nuevo (Día 0) y tiene los metadatos correctos, TrueSight no lo detectará hasta que VirusTotal lo reconozca.

## 🔒 Privacidad
*   Las API Keys se guardan localmente.
*   Solo se envían **Hashes** (huellas digitales) a VirusTotal, nunca tus archivos completos.

## 🤝 Créditos
Desarrollado como proyecto de aprendizaje sobre sistemas de archivos y APIs REST en .NET.
Refactorizado con asistencia de IA.
