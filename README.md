# 🛡️ AntivirusScanner (C# Edition)

Un escáner de antivirus ligero y rápido escrito en **C# (.NET 10)**, diseñado para monitorizar tu carpeta de **Descargas** de forma inteligente. Utiliza un sistema híbrido de detección (Metadatos + Hashing) e integración con la API de **VirusTotal**.

![License](https://img.shields.io/badge/license-MIT-blue.svg) ![Platform](https://img.shields.io/badge/platform-Windows-lightgrey) ![.NET](https://img.shields.io/badge/.NET-10.0-purple)

## ✨ Características

*   **⚡ Escaneo Híbrido Inteligente**:
    *   **Capa 1 (Metadatos)**: Ignora instantáneamente archivos que no han cambiado (comparando fecha y tamaño).
    *   **Capa 2 (Historial de Hash)**: Reconoce archivos seguros previamente analizados, incluso si se mueven o renombran.
    *   **Capa 3 (Análisis Profundo)**: Solo consulta a la nube (VirusTotal) si el archivo es nuevo y sospechoso.
*   **🔎 Detección Local de Spoofing**: Detecta archivos con extensiones falsas (ej. `documento.pdf.exe` o ejecutables disfrazados de imágenes) sin necesidad de internet.
*   **☁️ Integración con VirusTotal**: Consulta hashes desconocidos contra la base de datos de 70+ antivirus.
*   **🖥️ Interfaz Moderna (WPF)**:
    *   Ventana de configuración inicial para ingresar tu API Key fácilmente.
    *   Detección automática de la carpeta "Descargas" (sin importar si tu Windows está en Español o Inglés).
*   **🚫 Cuarentena**: Aísla automáticamente las amenazas detectadas en una carpeta segura.

## 🚀 Requisitos

*   Sistema Operativo: **Windows 10 / 11**
*   **.NET 10 SDK** (o Runtime) instalado.
    *   [Descargar .NET 10](https://dotnet.microsoft.com/download)

## 📦 Instalación y Uso

### 1. Clonar el repositorio
```bash
git clone https://github.com/tu-usuario/AntivirusScanner.git
cd AntivirusScanner
```

### 2. Compilar
Abre una terminal en la carpeta del proyecto y ejecuta:
```powershell
dotnet build -c Release
```

### 3. Ejecutar
```powershell
dotnet run --configuration Release
```
o ve a la carpeta `bin\Release\net10.0-windows\` y haz doble clic en `AntivirusScanner.exe`.

### 4. Configuración Inicial
La primera vez que lo inicies, se abrirá una ventana pidiéndote:
1.  **Tu API Key de VirusTotal** (Consíguela gratis en [virustotal.com](https://www.virustotal.com/gui/join-us)).
2.  Confirmar la carpeta a escanear.

![Config Screen](https://via.placeholder.com/400x200?text=Configuracion+Inicial+WPF)

## 🛠️ Estructura del Proyecto

*   `Program.cs`: Punto de entrada. Decide si lanzar la consola o la configuración.
*   `Core/Scanner.cs`: cerebro del antivirus (Lógica de Hashing y API).
*   `UI/ConfigWindow.cs`: Ventana gráfica (WPF) para ajustes.
*   `Utils/`: Utilidades para manejo seguro de rutas y JSON.

## ⚠️ Disclaimer

Este software es una herramienta **educativa** y de **segunda opinión**. No reemplaza a una suite de seguridad completa (como Windows Defender o Bitdefender). Úsalo bajo tu propia responsabilidad.

---
Creado con ❤️ y C#.
