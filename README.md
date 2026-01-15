# 🛡️ TruelSigth Antivirus

**TruelSigth** es una solución de seguridad moderna y ligera desarrollada en **C# (.NET 10)**. Diseñada para ofrecer una segunda capa de protección robusta, combina análisis heurístico local con la inteligencia en la nube de **VirusTotal**.

![Status](https://img.shields.io/badge/status-Active-brightgreen) ![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-blue) ![License](https://img.shields.io/badge/license-OS--Privado-orange) ![Type](https://img.shields.io/badge/Project-Educational-yellow)

> 🎓 **Nota:** Este es un proyecto desarrollado con fines **académicos y de aprendizaje**. No está afiliado a ninguna marca comercial.

## ✨ Características Principales

### 🛡️ Protección en Tiempo Real
- **Monitor Activo**: Vigila tu carpeta seleccionada (por defecto *Descargas*) las 24 horas del día.
- **Intercepción Inmediata**: Detecta nuevos archivos al instante de ser creados o modificados.
- **Bajo Consumo**: Se minimiza en la bandeja del sistema (reloj) consumiendo recursos mínimos mientras te protege.

### 🧠 Motor de Análisis Híbrido
1.  **Capa Rápida (Caché)**: Recuerda archivos analizados previamente para no gastar CPU innecesariamente.
2.  **Capa Local (Anti-Spoofing)**:
    *   Detecta **"Extensiones Dobles"** falsas (ej: `factura.pdf.exe`).
    *   Verifica **Firmas Mágicas (Magic Numbers)** para descubrir ejecutables disfrazados de imágenes o texto.
3.  **Capa Nube (VirusTotal API)**:
    *   Consulta el hash del archivo contra más de 70 motores antivirus mundiales.
    *   *(Requiere API Key gratuita)*.

### 🖥️ Interfaz Premium (WPF)
- Diseño moderno "Dark Mode" con efectos visuales.
- Dashboard intuitivo con estado de protección y estadísticas.
- Historial de amenazas detectadas.
- Configuración persistente (Inicio con Windows, Minimizado, etc.).

## 🚀 Instalación y Uso

Este es un proyecto de **Código Abierto** (actualmente en fase privada). Para usarlo:

### Requisitos
- **Windows 10 o 11** (64 bits).
- **.NET 10 Runtime** (si no usas la versión autocontenida).

### Compilación (para Desarrolladores)
1.  Clona este repositorio.
2.  Abre el proyecto en tu terminal o Visual Studio.
3.  Compila y ejecuta:
    ```powershell
    dotnet build -c Release
    dotnet run
    ```

### Primeros Pasos
1.  **Inicia la App**: Verás el Dashboard principal.
2.  **Configura tu API Key**:
    *   Ve a *Configuración*.
    *   Ingresa tu API Key de VirusTotal (puedes obtener una gratis en [virustotal.com](https://www.virustotal.com)).
    *   *Nota:* Sin la Key, la app funcionará pero solo con detección local (Spoofing).
3.  **Activa el Monitor**: Asegúrate de que el interruptor esté en **"ON"**.
4.  **Siéntete Seguro**: Minimiza la ventana. TruelSigth seguirá trabajando desde la barra de tareas.

## ⚠️ Limitaciones Actuales

*   **API Key Requerida**: Para la máxima protección (detección de virus complejos), es indispensable la conexión a VirusTotal.
*   **Enfoque de Carpeta**: Actualmente diseñado para monitorear una carpeta crítica (ej. Descargas), no todo el disco duro simultáneamente (para optimizar rendimiento).
*   **Plataforma**: Exclusivo para Windows (WPF).

## 🧪 Cómo Probar la Detección (Sin Riesgos)

El proyecto incluye un archivo llamado `test_threat.txt` para verificar que el antivirus funciona correctamente sin infectar tu PC.

### ¿Cómo funciona este archivo?
Es un archivo de texto inofensivo, pero contiene una **cabecera falsa** que simula ser un ejecutable (`MZ...`).
1.  **El Engaño**: Windows cree que es texto (`.txt`), pero TruelSigth lee sus primeros bytes y ve que dice ser un programa (`.exe`).
2.  **La Detección**: Al notar que la extensión no coincide con su contenido real, el motor **Anti-Spoofing** lo marca como una amenaza de "Doble Extensión" o "Ejecutable Oculto".
3.  **La Prueba**: Copia este archivo a tu carpeta de Descargas (con el monitor activo) y verás cómo es interceptado y enviado a cuarentena al instante.

## 🔒 Privacidad y Seguridad

*   **Tus Datos**: Las API Keys se guardan localmente en tu PC (`%APPDATA%\TruelSigth`). No se envían a ningún servidor externo salvo a VirusTotal (solo los hashes de los archivos).
*   **Cuarentena Segura**: Las amenazas detectadas se mueven a una carpeta aislada (`Quarantine`) y **se bloquean sus permisos (ACL)** automáticamente. 
    *   *Detalle Técnico:* El antivirus elimina todos los permisos de ejecución del archivo, dejándolo solo con permisos de lectura para el propietario. Esto evita que el malware se ejecute accidentalmente.

## 🤝 Agradecimientos

*   Desarrollado como proyecto educativo.
*   Código refactorizado y optimizado con la asistencia de IA (**Antigravity**).

---
*TruelSigth - Tu segunda opinión de confianza.*
