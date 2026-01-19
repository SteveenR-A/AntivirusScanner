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
        
        // Events for UI
        public event Action<string>? OnScanStarted;
        public event Action<ScanResult>? OnScanCompleted;
        public event Action<string>? OnThreatFound;

        public Scanner(AppConfig config)
        {
            _config = config;
            _vtService = new VirusTotalService();
        }

        public void UpdateConfig(AppConfig newConfig)
        {
            _config = newConfig;
        }

        public async Task RunFullScan()
        {
            if (!Directory.Exists(_config.TargetFolder)) return;

            // Safe Recursive Scan
            await Task.Run(async () => 
            {
                foreach (var file in GetSafeFiles(_config.TargetFolder))
                {
                    await ScanFile(file);
                }
            });
            
            // Save state after full scan
            SettingsManager.Save(_config);
        }

        private IEnumerable<string> GetSafeFiles(string rootPath)
        {
            var pending = new Stack<string>();
            pending.Push(rootPath);

            while (pending.Count > 0)
            {
                var path = pending.Pop();
                string[]? files = null;
                try
                {
                    files = Directory.GetFiles(path);
                }
                catch (UnauthorizedAccessException) { /* Skip locked folders */ }
                catch (Exception) { /* Skip other errors */ }

                if (files != null)
                {
                    foreach (var file in files) yield return file;
                }

                try
                {
                    foreach (var subdir in Directory.GetDirectories(path))
                    {
                        pending.Push(subdir);
                    }
                }
                catch { /* Ignore directory access errors */ }
            }
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

                // 1. Capa Rápida (Smart Cache)
                bool potentialCacheHit = TryGetCachedState(filePath, fileInfo, out var cachedState);

                // 2. ALWAYS Calculate Hash & Refresh Metadata (TOCTOU Fix)
                string hash = ComputeSha256(filePath);
                if (string.IsNullOrEmpty(hash)) 
                {
                    result.Status = ScanStatus.Error;
                    return result;
                }
                fileInfo.Refresh(); 

                // 3. ALWAYS Run Local Heuristics (Hybrid Scan)
                result = PerformLocalScan(filePath);

                // 4. Cloud Check (VirusTotal) - with TTL & Cache Logic
                if (result.Status == ScanStatus.Safe)
                {
                    result = await PerformCloudScan(filePath, hash, potentialCacheHit, cachedState, result);
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

        private bool TryGetCachedState(string filePath, FileInfo fileInfo, out FileState? cachedState)
        {
            cachedState = null;
            if (_config.FileStates.TryGetValue(filePath, out var oldState) && 
                oldState.LastModified == fileInfo.LastWriteTimeUtc && 
                oldState.Size == fileInfo.Length)
            {
                cachedState = oldState;
                return true;
            }
            return false;
        }

        private static ScanResult PerformLocalScan(string filePath)
        {
            // A. Local Signatures
            var localMetadata = LocalScanner.CheckLocalSignatures(filePath);
            if (localMetadata.Status != ScanStatus.Safe)
            {
                return localMetadata;
            }

            // B. Byte Patterns & Entropy
            return LocalScanner.ScanFileContent(filePath);
        }

        private async Task<ScanResult> PerformCloudScan(string filePath, string hash, bool potentialCacheHit, FileState? cachedState, ScanResult currentResult)
        {
            // If Local is CLEAN, we can check Cache to skip VT
            if (potentialCacheHit && cachedState != null && cachedState.Status == ScanStatus.Safe.ToString())
            {
                // Check TTL (Smart Strategy)
                int ttlDays = IsCriticalFile(filePath) ? 7 : 30;
                
                var age = DateTime.UtcNow - cachedState.LastScanned;
                if (age.TotalDays < ttlDays)
                {
                    return new ScanResult { FilePath = filePath, Status = ScanStatus.Skipped, Details = currentResult.Details };
                }
            }

            // Also check HashHistory (for moved files)
            if (_config.BlacklistedHashes.Contains(hash))
            {
                return new ScanResult 
                { 
                    FilePath = filePath, 
                    Status = ScanStatus.Threat, 
                    ThreatType = ThreatType.Malware, 
                    Details = "Detected by Local Blacklist" 
                };
            }
            
            // If still considered Safe locally, check VT
            if (!string.IsNullOrEmpty(_config.ApiKey))
            {
                int vtDetections = await _vtService.CheckFileHashAsync(hash, _config.ApiKey);
                if (vtDetections > 0)
                {
                    _config.BlacklistedHashes.Add(hash);
                    return new ScanResult 
                    { 
                        FilePath = filePath, 
                        Status = ScanStatus.Threat, 
                        ThreatType = ThreatType.Malware, 
                        Details = $"VirusTotal: {vtDetections} detections" 
                    };
                }
                else if (vtDetections == 0)
                {
                     return currentResult;
                }
                else
                {
                    return new ScanResult 
                    { 
                        FilePath = filePath, 
                        Status = ScanStatus.Error, 
                        Details = "VirusTotal Scan Failed (Offline/Limit)" 
                    }; 
                }
            }
            
            return currentResult;
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
                
                 // Update State with LastScanned = Now
                _config.FileStates[result.FilePath] = new FileState 
                { 
                    LastModified = fileInfo.LastWriteTimeUtc, 
                    Size = fileInfo.Length, 
                    Hash = hash,
                    Status = ScanStatus.Safe.ToString(),
                    LastScanned = DateTime.UtcNow // REVALIDATION TIMESTAMP
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
                // Rename to .quarantine to prevent execution
                string newName = $"{Guid.NewGuid()}_{fileName}.quarantine";
                string destPath = Path.Combine(quarantineDir, newName);

                File.Move(filePath, destPath);
                
                // Remove Permissions (Lock down the file) - Windows Specific
                try
                {
                    var fileInfo = new FileInfo(destPath);
                    var security = fileInfo.GetAccessControl();
                    
                    // Break inheritance
                    security.SetAccessRuleProtection(true, false);
                    
                    // Grant SYSTEM Full Control (so app/admin can still manage it)
                    security.AddAccessRule(new FileSystemAccessRule(
                        new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                        FileSystemRights.FullControl,
                        AccessControlType.Allow));

                    // Grant User DELETE & WRITE Only (No Execute, No Read Data)
                    var user = WindowsIdentity.GetCurrent().Name;
                    var rule = new FileSystemAccessRule(
                        user, 
                        FileSystemRights.Delete | FileSystemRights.Write | FileSystemRights.ReadAttributes, 
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
        private bool IsCriticalFile(string filePath)
        {
            try
            {
                string ext = Path.GetExtension(filePath).ToLower();
                return ext == ".exe" || ext == ".dll" || ext == ".bat" || ext == ".ps1" || 
                       ext == ".msi" || ext == ".vbs" || ext == ".js" || ext == ".cmd" || ext == ".com";
            }
            catch { return false; }
        }
    }
}
