using System;
using System.IO;
using System.Security.AccessControl;
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
    public class ScanResult
    {
        public string FilePath { get; set; } = "";
        public bool IsSafe { get; set; }
        public bool IsSkipped { get; set; }
        public string ThreatType { get; set; } = "";
        public string Details { get; set; } = "";
    }

    public class Scanner
    {
        private AppConfig _config;
        private static readonly HttpClient _client = new HttpClient();
        
        // Events for UI
        public event Action<string>? OnScanStarted;
        public event Action<ScanResult>? OnScanCompleted;
        public event Action<string>? OnThreatFound;

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

        public void UpdateConfig(AppConfig newConfig)
        {
            _config = newConfig;
        }

        public async Task RunFullScan()
        {
            if (!Directory.Exists(_config.TargetFolder)) return;

            var files = Directory.GetFiles(_config.TargetFolder);
            int threats = 0;
            int skipped = 0;

            foreach (var file in files)
            {
                var result = await ScanFile(file);
                if (result.IsSkipped) skipped++;
                if (!result.IsSafe) threats++;
            }
            
            // Save state after full scan
            SettingsManager.Save(_config);
        }

        public async Task<ScanResult> ScanFile(string filePath)
        {
            var result = new ScanResult { FilePath = filePath, IsSafe = true };
            
            if (!File.Exists(filePath)) return result;

            try
            {
                var fileInfo = new FileInfo(filePath);
                OnScanStarted?.Invoke(Path.GetFileName(filePath));

                // 1. Capa Rápida (Cache Check)
                if (_config.FileStates.TryGetValue(filePath, out var oldState))
                {
                    if (oldState.LastModified == fileInfo.LastWriteTimeUtc && oldState.Size == fileInfo.Length)
                    {
                        if (oldState.Status == "SAFE")
                        {
                            result.IsSkipped = true;
                            OnScanCompleted?.Invoke(result);
                            return result;
                        }
                    }
                }

                Console.WriteLine($"🔎 Analizando: {Path.GetFileName(filePath)}...");
                
                string hash = ComputeSha256(filePath);
                if (string.IsNullOrEmpty(hash)) return result;

                bool suspicious = false;
                string reason = "";

                // 2. Capa Histórica (Known Hash)
                if (_config.HashHistory.TryGetValue(hash, out var status) && status == "SAFE")
                {
                    // Already safe, do nothing
                }
                else
                {
                    // 3. Análisis Profundo
                    
                    // A. Análisis Local (Firmas)
                    string magic = GetMagicNumber(filePath);
                    string ext = Path.GetExtension(filePath).ToLower();

                    foreach (var sig in Signatures)
                    {
                        if (magic.StartsWith(sig.Key))
                        {
                            bool validExt = false;
                            foreach (var valid in sig.Value.Exts) if (ext == valid) validExt = true;

                            if (!validExt)
                            {
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
                           _config.HashHistory[hash] = "SAFE";
                        }
                    }
                }

                if (suspicious)
                {
                    result.IsSafe = false;
                    result.ThreatType = "Malware/Spoofing";
                    result.Details = reason;
                    
                    MoveToQuarantine(filePath, reason);
                    OnThreatFound?.Invoke($"Amenaza: {Path.GetFileName(filePath)} ({reason})");
                }
                else
                {
                    result.IsSafe = true;
                    _config.HashHistory[hash] = "SAFE";
                }

                // Update State
                if (result.IsSafe && File.Exists(filePath))
                {
                    _config.FileStates[filePath] = new FileState 
                    { 
                        LastModified = fileInfo.LastWriteTimeUtc, 
                        Size = fileInfo.Length, 
                        Hash = hash,
                        Status = "SAFE"
                    };
                }
                
                if (!result.IsSkipped) SettingsManager.Save(_config);

                OnScanCompleted?.Invoke(result);
                return result;

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error scanning file: {ex.Message}");
                return result;
            }
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
                if (br.BaseStream.Length < 4) return "";
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
                    await Task.Delay(5000); // Wait bit
                    return -1; // Skip for now or retry logic
                }

                response.EnsureSuccessStatusCode();
                string json = await response.Content.ReadAsStringAsync();
                
                using var doc = JsonDocument.Parse(json);
                var stats = doc.RootElement.GetProperty("data").GetProperty("attributes").GetProperty("last_analysis_stats");
                return stats.GetProperty("malicious").GetInt32();
            }
            catch
            {
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

                // Ensure unique name
                if (File.Exists(destPath)) destPath += ".virus";

                File.Move(filePath, destPath);
                
                // Remove Permissions (Lock down the file)
                try
                {
                    var fileInfo = new FileInfo(destPath);
                    var security = fileInfo.GetAccessControl();
                    
                    // Disable inheritance and remove all existing rules
                    security.SetAccessRuleProtection(true, false);
                    
                    // Add Read-Only access for the current user (Owner)
                    var user = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
                    var rule = new FileSystemAccessRule(
                        user, 
                        FileSystemRights.ReadData, 
                        AccessControlType.Allow);
                        
                    security.AddAccessRule(rule);
                    fileInfo.SetAccessControl(security);
                }
                catch (Exception aclEx)
                {
                    Console.WriteLine($"Error cambiando permisos ACL: {aclEx.Message}");
                }

                File.WriteAllText(destPath + ".txt", $"Original: {filePath}\nDate: {DateTime.Now}\nReason: {reason}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error moviendo a cuarentena: {ex.Message}");
            }
        }
    }
}
