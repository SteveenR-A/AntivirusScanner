# TrueSight Scanner v1.0.0 (Educational Release) 🛡️

¡Primera versión pública de **TrueSight Scanner**! 🚀

Este proyecto es una **herramienta educativa de escaneo de archivos** diseñada para demostrar cómo funcionan las verificaciones de integridad y la reputación en la nube.

> [!WARNING]
> **Prueba de Concepto**: Este software no sustituye a tu antivirus principal. Úsalo para verificar archivos sospechosos manualmente o monitorear descargas.

## ✨ Funcionalidades
*   **Anti-Spoofing:** Detecta archivos con "doble extensión" o cabeceras falsas (ej. un `.exe` disfrazado de `.txt`).
*   **Integración VirusTotal:** Consulta hashes en la nube para detectar malware conocido.
*   **Smart Rate-Limit:** Respeta automáticamente el límite de la API gratuita de VirusTotal (4 peticiones/minuto).
*   **UI Educativa:** Interfaz WPF moderna para visualizar los procesos de detección.
*   **Cuarentena:** Aísla archivos detectados quitándoles permisos de ejecución (ACL).

## 📦 Cómo Probarlo
Este lanzamiento es **Solo Código Fuente** (Source Code Only).

1.  Descarga el código fuente (`Source code (zip)` abajo).
2.  Asegúrate de tener instalado el [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0).
3.  Descomprime y ejecuta en tu terminal:
    ```powershell
    dotnet build -c Release
    dotnet run
    ```
4.  Configura tu API Key y ¡listo!

## 📝 Notas Técnicas
*   Requiere **Windows 10/11**.
*   **Limitaciones:** No escanea memoria, no elimina virus activos, solo analiza archivos estáticos.

---
*Desarrollado con fines de aprendizaje.*
