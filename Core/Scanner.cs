using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Net.Http;
using System.Text.Json;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Windows;
using AntivirusScanner.Utils;

namespace AntivirusScanner.Core
{
    public class Scanner
    {
        private AppConfig _config;
        private static readonly HttpClient _client = new HttpClient();
        
        // Firmas peligrosas (Magic Numbers)
        private static readonly Dictionary<string, (string Desc, string[] Exts)> Signatures = new()
        {
            { "7f454c46", ("ELF (Linux)", new[] { ".elf", ".bin", ".o", ".so" }) },
            { "4d5a",     ("EXE (Windows)", new[] { ".exe", ".dll", ".msi", ".com", ".sys" }) },
            { "25504446", ("PDF", new[] { ".pdf" }) },
            { "504b0304", ("ZIP/Office", new[] { ".zip", ".jar", ".apk", ".docx", ".xlsx" }) }
        };

        private static readonly string[] MaskExtensions = { ".jpg", ".png", ".txt", ".mp4", ".doc", ".pdf" };

        public Scanner(AppConfig config)
        {
            _config = config;
        }

        public async Task RunScan()
        {
            Console.WriteLine($"\n🛡️  Iniciando escaneo en: {_config.TargetFolder}");
            if (!Directory.Exists(_config.TargetFolder))
            {
                Console.WriteLine("❌ Carpeta no encontrada.");
                return;
            }

            var files = Directory.GetFiles(_config.TargetFolder);
            var newFileStates = new Dictionary<string, FileState>();
            int threats = 0;
            int skipped = 0;

            foreach (var file in files)
            {
                var fileInfo = new FileInfo(file);
                
                // 1. Capa Rápida (Metadatos)
                if (_config.FileStates.TryGetValue(file, out var oldState))
                {
                    if (oldState.LastModified == fileInfo.LastWriteTimeUtc && oldState.Size == fileInfo.Length)
                    {
                        newFileStates[file] = oldState; // Intacto
                        skipped++;
                        continue;
                    }
                }

                Console.WriteLine($"🔎 Analizando: {Path.GetFileName(file)}...");
                
                // Calcular Hash
                string hash = ComputeSha256(file);
                if (string.IsNullOrEmpty(hash)) continue;

                bool isSafe = false;

                // 2. Capa Histórica
                if (_config.HashHistory.TryGetValue(hash, out var status) && status == "SAFE")
                {
                    isSafe = true;
                }
                else
                {
                    // 3. Análisis Profundo
                    bool suspicious = false;
                    string reason = "";

                    // A. Análisis Local (Firmas)
                    string magic = GetMagicNumber(file);
                    string ext = Path.GetExtension(file).ToLower();

                    foreach (var sig in Signatures)
                    {
                        if (magic.StartsWith(sig.Key))
                        {
                            bool validExt = false;
                            foreach (var valid in sig.Value.Exts) if (ext == valid) validExt = true;

                            if (!validExt)
                            {
                                // Posible spoofing
                                foreach (var mask in MaskExtensions)
                                    if (ext == mask) { suspicious = true; reason = $"Spoofing ({sig.Value.Desc} como {ext})"; }
                                
                                if (!suspicious && sig.Key == "4d5a") { suspicious = true; reason = "Ejecutable oculto"; }
                            }
                            break;
                        }
                    }

                    // B. VirusTotal
                    if (!suspicious && !string.IsNullOrEmpty(_config.ApiKey))
                    {
                        int vtResult = await CheckVirusTotal(hash, _config.ApiKey);
                        if (vtResult > 0)
                        {
                            suspicious = true;
                            reason = $"VirusTotal: {vtResult} detecciones";
                        }
                        else if (vtResult == 0)
                        {
                            isSafe = true;
                            _config.HashHistory[hash] = "SAFE";
                        }
                    }

                    if (suspicious)
                    {
                        Console.WriteLine($"🚨 AMENAZA DETECTADA: {reason}");
                        MoveToQuarantine(file, reason);
                        threats++;
                        MessageBox.Show($"Amenaza detectada:\n{Path.GetFileName(file)}\n\nMotivo: {reason}\n\nMovido a Cuarentena.", "ALERTA VIRUS", MessageBoxButton.OK, MessageBoxImage.Warning);
                        continue; // No agregamos a safe states
                    }
                    else
                    {
                        // Si pasó todas las pruebas y no es sospechoso, asumimos seguro por ahora
                        isSafe = true;
                         _config.HashHistory[hash] = "SAFE";
                    }
                }

                if (isSafe)
                {
                    newFileStates[file] = new FileState 
                    { 
                        LastModified = fileInfo.LastWriteTimeUtc, 
                        Size = fileInfo.Length, 
                        Hash = hash 
                    };
                }
            }

            _config.FileStates = newFileStates;
            SettingsManager.Save(_config);

            Console.WriteLine($"\n✅ Escaneo completado.");
            Console.WriteLine($"   - Saltados (Sin cambios): {skipped}");
            Console.WriteLine($"   - Amenazas: {threats}");
        }

        private string ComputeSha256(string filePath)
        {
            try
            {
                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(filePath);
                var hash = sha256.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
            catch { return ""; }
        }

        private string GetMagicNumber(string filePath)
        {
            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read);
                using var br = new BinaryReader(fs);
                byte[] bytes = br.ReadBytes(4);
                return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
            }
            catch { return ""; }
        }

        private async Task<int> CheckVirusTotal(string hash, string apiKey)
        {
            try
            {
                _client.DefaultRequestHeaders.Clear();
                _client.DefaultRequestHeaders.Add("x-apikey", apiKey);
                
                var response = await _client.GetAsync($"https://www.virustotal.com/api/v3/files/{hash}");
                
                if (response.StatusCode == System.Net.HttpStatusCode.NotFound) return 0;
                if (response.StatusCode == System.Net.HttpStatusCode.TooManyRequests) 
                {
                    Console.WriteLine("   ⏳ Límite API. Esperando 15s...");
                    await Task.Delay(15000);
                    return await CheckVirusTotal(hash, apiKey);
                }

                response.EnsureSuccessStatusCode();
                string json = await response.Content.ReadAsStringAsync();
                
                using var doc = JsonDocument.Parse(json);
                var stats = doc.RootElement.GetProperty("data").GetProperty("attributes").GetProperty("last_analysis_stats");
                return stats.GetProperty("malicious").GetInt32();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"   ⚠️ Error VT: {ex.Message}");
                return -1;
            }
        }

        private void MoveToQuarantine(string filePath, string reason)
        {
            try
            {
                string quarantineDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Quarantine");
                if (!Directory.Exists(quarantineDir)) Directory.CreateDirectory(quarantineDir);

                string fileName = Path.GetFileName(filePath);
                string newName = $"{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}_{fileName}";
                string destPath = Path.Combine(quarantineDir, newName);

                File.Move(filePath, destPath);
                
                // Crear nota
                File.WriteAllText(destPath + ".txt", $"Original: {filePath}\nDate: {DateTime.Now}\nReason: {reason}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error moviendo a cuarentena: {ex.Message}");
            }
        }
    }
}
