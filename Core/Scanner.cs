using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Windows;
using AntivirusScanner.Utils;
using System.Security.Cryptography;

namespace AntivirusScanner.Core
{
    public class Scanner
    {
        private AppConfig _config;
        private readonly VirusTotalService _vtService;
        private readonly LocalScanner _localScanner;
        
        // Events for UI
        public event Action<string>? OnScanStarted;
        public event Action<ScanResult>? OnScanCompleted;
        public event Action<string>? OnThreatFound;

        public Scanner(AppConfig config)
        {
            _config = config;
            _vtService = new VirusTotalService();
            _localScanner = new LocalScanner();
        }

        public void UpdateConfig(AppConfig newConfig)
        {
            _config = newConfig;
        }

        public async Task RunFullScan()
        {
            if (!Directory.Exists(_config.TargetFolder)) return;

            var files = Directory.GetFiles(_config.TargetFolder);
            
            foreach (var file in files)
            {
                await ScanFile(file);
            }
            
            // Save state after full scan
            SettingsManager.Save(_config);
        }

        public async Task<ScanResult> ScanFile(string filePath)
        {
            var result = new ScanResult { FilePath = filePath, Status = ScanStatus.Safe };
            
            if (!File.Exists(filePath)) 
            {
                result.Status = ScanStatus.Error;
                result.Details = "File not found";
                return result;
            }

            try
            {
                var fileInfo = new FileInfo(filePath);
                OnScanStarted?.Invoke(Path.GetFileName(filePath));

                // 1. Capa Rápida (Cache Check)
                if (_config.FileStates.TryGetValue(filePath, out var oldState))
                {
                    if (oldState.LastModified == fileInfo.LastWriteTimeUtc && oldState.Size == fileInfo.Length)
                    {
                        if (oldState.Status == ScanStatus.Safe.ToString())
                        {
                            result.Status = ScanStatus.Skipped;
                            OnScanCompleted?.Invoke(result);
                            return result;
                        }
                    }
                }

                string hash = ComputeSha256(filePath);
                if (string.IsNullOrEmpty(hash)) 
                {
                    result.Status = ScanStatus.Error;
                    return result;
                }

                // 2. Capa Histórica (Known Hash) & BLACKLIST (Offline)
                if (_config.BlacklistedHashes.Contains(hash))
                {
                    result.Status = ScanStatus.Threat;
                    result.ThreatType = ThreatType.Malware;
                    result.Details = "Detected by Local Blacklist";
                    HandleAction(result, hash, fileInfo);
                    return result;
                }

                if (_config.HashHistory.TryGetValue(hash, out var status) && status == ScanStatus.Safe.ToString())
                {
                    result.Status = ScanStatus.Safe;
                    OnScanCompleted?.Invoke(result);
                    return result; // Already safe
                }

                // 3. Análisis Profundo
                
                // A. Análisis Local (Firmas & Heurística)
                var localMetadata = _localScanner.CheckLocalSignatures(filePath);
                if (localMetadata.Status != ScanStatus.Safe)
                {
                    result = localMetadata;
                    // Dont return yet, we might want to verify with VT if just suspicious? for now return
                }
                else
                {
                    // Heurística de strings
                    var heuristic = _localScanner.ScanFileContent(filePath);
                    if (heuristic.Status != ScanStatus.Safe)
                    {
                        result = heuristic;
                    }
                    else
                    {
                        // B. VirusTotal
                        if (!string.IsNullOrEmpty(_config.ApiKey))
                        {
                            int vtDetections = await _vtService.CheckFileHashAsync(hash, _config.ApiKey);
                            if (vtDetections > 0)
                            {
                                result.Status = ScanStatus.Threat;
                                result.ThreatType = ThreatType.Malware;
                                result.Details = $"VirusTotal: {vtDetections} detections";
                                
                                // Save to Blacklist
                                _config.BlacklistedHashes.Add(hash);
                            }
                            else if (vtDetections == 0)
                            {
                                 result.Status = ScanStatus.Safe;
                            }
                            // If -1 (Error/RateLimit), we default to Safe locally but don't cache as Safe
                        }
                    }
                }

                HandleAction(result, hash, fileInfo);
                return result;

            }
            catch (Exception ex)
            {
                result.Status = ScanStatus.Error;
                result.Details = ex.Message;
                return result;
            }
        }

        private void HandleAction(ScanResult result, string hash, FileInfo fileInfo)
        {
            // 4. Acción y Persistencia
            if (result.Status == ScanStatus.Threat || result.Status == ScanStatus.Suspicious)
            {
                MoveToQuarantine(result.FilePath, result.Details);
                OnThreatFound?.Invoke($"THREAT: {Path.GetFileName(result.FilePath)} ({result.Details})");
            }
            else if (result.Status == ScanStatus.Safe)
            {
                _config.HashHistory[hash] = ScanStatus.Safe.ToString();
                
                 // Update State
                _config.FileStates[result.FilePath] = new FileState 
                { 
                    LastModified = fileInfo.LastWriteTimeUtc, 
                    Size = fileInfo.Length, 
                    Hash = hash,
                    Status = ScanStatus.Safe.ToString()
                };
            }

            if (result.Status != ScanStatus.Skipped) 
                SettingsManager.Save(_config);

            OnScanCompleted?.Invoke(result);
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

        private void MoveToQuarantine(string filePath, string reason)
        {
            try
            {
                string quarantineDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Quarantine");
                if (!Directory.Exists(quarantineDir)) Directory.CreateDirectory(quarantineDir);

                string fileName = Path.GetFileName(filePath);
                // Use GUID to prevent collisions
                string newName = $"{Guid.NewGuid()}_{fileName}";
                string destPath = Path.Combine(quarantineDir, newName);

                File.Move(filePath, destPath);
                
                // Remove Permissions (Lock down the file) - Windows Specific
                try
                {
                    var fileInfo = new FileInfo(destPath);
                    var security = fileInfo.GetAccessControl();
                    
                    security.SetAccessRuleProtection(true, false);
                    
                    var user = WindowsIdentity.GetCurrent().Name;
                    var rule = new FileSystemAccessRule(
                        user, 
                        FileSystemRights.ReadData, 
                        AccessControlType.Allow);
                        
                    security.AddAccessRule(rule);
                    fileInfo.SetAccessControl(security);
                }
                catch (Exception)
                {
                    // Fail silently for ACL errors
                }

                File.WriteAllText(destPath + ".txt", $"Original: {filePath}\nDate: {DateTime.Now}\nReason: {reason}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error moving to quarantine: {ex.Message}");
            }
        }
    }
}
