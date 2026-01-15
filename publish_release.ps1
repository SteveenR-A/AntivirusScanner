# Script para Construir y Empaquetar TrueSight para GitHub
$ErrorActionPreference = "Stop"

Write-Host "🚀 Iniciando compilación de TrueSight Release..." -ForegroundColor Cyan

# 1. Limpiar y Compilar (Single File)
dotnet publish -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -p:DebugType=None

if ($LASTEXITCODE -ne 0) {
    Write-Error "Error en la compilación."
}

# Rutas
$SourceFile = "bin\Release\net10.0-windows\win-x64\publish\TrueSight.exe"
$ReleaseDir = "Releases"
$ZipName = "$ReleaseDir\TrueSight_v1.0.zip"



# 2. Crear carpeta de Releases
if (!(Test-Path $ReleaseDir)) {
    New-Item -ItemType Directory -Force -Path $ReleaseDir | Out-Null
}

# 3. Empaquetar en ZIP (Requiere Powershell 5+)
if (Test-Path $ZipName) { Remove-Item $ZipName }

Compress-Archive -Path $SourceFile -DestinationPath $ZipName -Force

Write-Host "✅ Archivo creado: $ZipName" -ForegroundColor Green
Write-Host "Listo para subir a GitHub Releases." -ForegroundColor Green

# 4. Copiar a Descargas (Solo si se solicita)
$DownloadsDir = "$env:USERPROFILE\Downloads"
Copy-Item $ZipName -Destination $DownloadsDir -Force
Write-Host "📥 Copia guardada en Descargas: $DownloadsDir\TrueSight_v1.0.zip" -ForegroundColor Cyan
Write-Host "📂 Abriendo carpeta..."

Invoke-Item $ReleaseDir
