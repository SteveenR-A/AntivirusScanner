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
                bool potentialCacheHit = false;
                FileState? cachedState = null;

                if (_config.FileStates.TryGetValue(filePath, out var oldState))
                {
                    // Check if file changed (Size/Time)
                    if (oldState.LastModified == fileInfo.LastWriteTimeUtc && oldState.Size == fileInfo.Length)
                    {
                        potentialCacheHit = true;
                        cachedState = oldState;
                    }
                    else
                    {
                        // File changed, invalidate cache (implicitly by not setting potentialCacheHit)
                    }
                }

                // 2. ALWAYS Calculate Hash & Refresh Metadata (TOCTOU Fix)
                string hash = ComputeSha256(filePath);
                if (string.IsNullOrEmpty(hash)) 
                {
                    result.Status = ScanStatus.Error;
                    return result;
                }
                fileInfo.Refresh(); 

                // 3. ALWAYS Run Local Heuristics (Hybrid Scan)
                // "Revalidación forzada si hay heurística sospechosa" -> We always check local signs.
                
                // A. Local Signatures
                var localMetadata = LocalScanner.CheckLocalSignatures(filePath);
                if (localMetadata.Status != ScanStatus.Safe)
                {
                    result = localMetadata;
                    // If local is suspicious, we might want to Confirm with VT (bypass cache)
                }
                else
                {
                    // B. Byte Patterns & Entropy
                    var heuristic = LocalScanner.ScanFileContent(filePath);
                    if (heuristic.Status != ScanStatus.Safe)
                    {
                        result = heuristic;
                    }
                }

                bool localIsClean = result.Status == ScanStatus.Safe;

                // 4. Cloud Check (VirusTotal) - with TTL & Cache Logic
                if (localIsClean)
                {
                    // If Local is CLEAN, we can check Cache to skip VT
                    if (potentialCacheHit && cachedState != null && cachedState.Status == ScanStatus.Safe.ToString())
                    {
                        // Check TTL (Smart Strategy)
                        // Critical files (exe, scripts) = 7 Days
                        // Passive files (txt, img) = 30 Days (Save API Quota)
                        int ttlDays = IsCriticalFile(filePath) ? 7 : 30;
                        
                        var age = DateTime.UtcNow - cachedState.LastScanned;
                        if (age.TotalDays < ttlDays)
                        {
                            result.Status = ScanStatus.Skipped; // Safe & Valid Cache
                            OnScanCompleted?.Invoke(result);
                            return result;
                        }
                        // Expired -> Fall through to VT
                    }

                    // Also check HashHistory (for moved files)
                    if (_config.BlacklistedHashes.Contains(hash))
                    {
                        result.Status = ScanStatus.Threat;
                        result.ThreatType = ThreatType.Malware;
                        result.Details = "Detected by Local Blacklist";
                    }
                    else if (_config.HashHistory.TryGetValue(hash, out var status) && status == ScanStatus.Safe.ToString())
                    {
                        // Hash known safe, BUT check if we need to re-verify due to TTL?
                        // HashHistory doesn't store date. We rely on FileState for TTL on specific files.
                        // If it's a new file with known hash, we ideally trust the hash... 
                        // BUT user wants weekly revalidation.
                        // For simplicity: If Cache (FileState) missed, we DO check VT to be safe, 
                        // unless we want to trust HashHistory globally. 
                        // Use a conservative approach: If FileState missed (new file), check VT. 
                        // HashHistory is a backup if VT fails or specific optimization.
                    
                        // Current logic: If HashHistory says safe, we return Safe.
                        // To implement "Weekly Revalidation" properly without bloating HashHistory with dates,
                        // we generally rely on FileState. 
                        // For now, let's allow HashHistory to skip VT, assuming HashHistory is cleared or managed elsewhere,
                        // OR we just accept that HashHistory implies "Global Trust".
                        
                        // However, to strictly follow "Revalidación semanal", we should probably NOT trust HashHistory 
                        // without a timestamp. Since HashHistory is simple <string, string>, it's timeless.
                        // Let's degrade HashHistory to "Soft Trust" -> If not in Blacklist, we check VT anyway 
                        // if we want strict freshness.
                        
                        // OPTIMIZATION: If we scanned this EXACT file path < 7 days ago, we skipped above.
                        // If we are here, either it's a new file or expired.
                        // So checking VT is the correct "Fresh" action.
                    }

                    // If still considered Safe locally, check VT
                    if (result.Status == ScanStatus.Safe && !string.IsNullOrEmpty(_config.ApiKey))
                    {
                        int vtDetections = await _vtService.CheckFileHashAsync(hash, _config.ApiKey);
                        if (vtDetections > 0)
                        {
                            result.Status = ScanStatus.Threat;
                            result.ThreatType = ThreatType.Malware;
                            result.Details = $"VirusTotal: {vtDetections} detections";
                            _config.BlacklistedHashes.Add(hash);
                        }
                        else if (vtDetections == 0)
                        {
                             result.Status = ScanStatus.Safe;
                        }
                        else
                        {
                            // Error/Limit -> Fail Open Fix from before
                            result.Status = ScanStatus.Error; 
                            result.Details = "VirusTotal Scan Failed (Offline/Limit)";
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
