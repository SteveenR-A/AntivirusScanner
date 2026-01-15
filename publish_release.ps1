# Script para Construir y Empaquetar TrueSight para GitHub
$ErrorActionPreference = "Stop"

Write-Host "🚀 Iniciando compilación de TrueSight Release..." -ForegroundColor Cyan

# 1. Limpiar y Compilar (Single File)
dotnet publish -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -p:DebugType=None

if ($LASTEXITCODE -ne 0) {
    Write-Error "La compilación falló."
    exit
}

# Rutas
$SourceFile = "bin\Release\net10.0-windows\win-x64\publish\TrueSight.exe"
$ReleaseDir = "Releases"
$ZipName = "$ReleaseDir\TrueSight_v1.0.zip"

# 2. Crear carpeta de Releases
if (!(Test-Path $ReleaseDir)) {
    New-Item -ItemType Directory -Force -Path $ReleaseDir | Out-Null
}

# 3. Empaquetar en ZIP (Recomendado para GitHub para evitar bloqueos de navegador)
Write-Host "📦 Creando archivo ZIP ($ZipName)..." -ForegroundColor Yellow
if (Test-Path $ZipName) { Remove-Item $ZipName }

Compress-Archive -Path $SourceFile -DestinationPath $ZipName

Write-Host "✅ ¡Listo! Archivo preparado para subir a GitHub Releases." -ForegroundColor Green
Write-Host "📂 Abriendo carpeta..."

Invoke-Item $ReleaseDir
