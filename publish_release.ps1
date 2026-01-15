# Script para Construir y Empaquetar TruelSigth para GitHub
$ErrorActionPreference = "Stop"

Write-Host "🚀 Iniciando compilación de TruelSigth Release..." -ForegroundColor Cyan

# 1. Limpiar y Compilar (Single File)
dotnet publish -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -p:DebugType=None

if ($LASTEXITCODE -ne 0) {
    Write-Error "Error en la compilación."
}

# Rutas
$SourceFile = "bin\Release\net10.0-windows\win-x64\publish\TruelSigth.exe"
$ReleaseDir = "Releases"
$ZipName = "$ReleaseDir\TruelSigth_v1.0.zip"

# Revertir cualquier nombre anterior si existe
if (Test-Path "bin\Release\net10.0-windows\win-x64\publish\TrueSight.exe") {
    Rename-Item "bin\Release\net10.0-windows\win-x64\publish\TrueSight.exe" "TruelSigth.exe"
}

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
Write-Host "📥 Copia guardada en Descargas: $DownloadsDir\TruelSigth_v1.0.zip" -ForegroundColor Cyan
Write-Host "📂 Abriendo carpeta..."

Invoke-Item $ReleaseDir
