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
        private readonly CloudScanQueue _cloudQueue;
        
        // Events for UI
        public event Action<string>? OnScanStarted;
        public event Action<ScanResult>? OnScanCompleted;
        public event Action<string>? OnThreatFound;

        public Scanner(AppConfig config)
        {
            _config = config;
            _cloudQueue = new CloudScanQueue(config);
            _cloudQueue.OnCloudResult += HandleCloudResult;
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

        private static IEnumerable<string> GetSafeFiles(string rootPath)
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
            if (!File.Exists(filePath)) 
                return new ScanResult { FilePath = filePath, Status = ScanStatus.Error, Details = "File not found" };

            try
            {
                var fileInfo = new FileInfo(filePath);
                OnScanStarted?.Invoke(Path.GetFileName(filePath));

                // 1. Capa Rápida (Smart Cache)
                bool potentialCacheHit = TryGetCachedState(filePath, fileInfo, out var cachedState);

                // 2. Calculate Hash (includes Size Check)
                if (!TryComputeHash(filePath, fileInfo, out string hash, out ScanResult? errorResult))
                {
                    return errorResult ?? new ScanResult { FilePath = filePath, Status = ScanStatus.Error };
                }
                
                fileInfo.Refresh(); 

                // 3. ALWAYS Run Local Heuristics (Hybrid Scan)
                var result = PerformLocalScan(filePath, hash);

                // 4. Cloud Check (VirusTotal) - Queue Strategy
                if (result.Status == ScanStatus.Safe)
                {
                    ProcessCloudStrategy(filePath, hash, potentialCacheHit, cachedState, ref result);
                }

                HandleAction(result, hash, fileInfo);
                return result;
            }
            catch (Exception ex)
            {
                return new ScanResult { FilePath = filePath, Status = ScanStatus.Error, Details = ex.Message };
            }
        }

        private bool TryComputeHash(string filePath, FileInfo fileInfo, out string hash, out ScanResult? errorResult)
        {
            hash = string.Empty;
            errorResult = null;

            if (fileInfo.Length >= 50 * 1024 * 1024)
            {
                errorResult = new ScanResult 
                { 
                    FilePath = filePath, 
                    Status = ScanStatus.Skipped, 
                    Details = "File too large for deep scan (>50MB)" 
                };
                return false;
            }

            hash = ComputeSha256(filePath);
            if (string.IsNullOrEmpty(hash))
            {
                errorResult = new ScanResult { FilePath = filePath, Status = ScanStatus.Error };
                return false;
            }

            return true;
        }

        private void ProcessCloudStrategy(string filePath, string hash, bool potentialCacheHit, FileState? cachedState, ref ScanResult result)
        {
            // Check Local Blacklist first
            if (_config.BlacklistedHashes.Contains(hash))
            {
                result.Status = ScanStatus.Threat;
                result.ThreatType = ThreatType.Malware;
                result.Details = "Detected by Local Blacklist";
                return;
            }

            // Check Cache TTL
            bool useCache = false;
            if (potentialCacheHit && cachedState != null && cachedState.Status == ScanStatus.Safe.ToString())
            {
                int ttlDays = IsCriticalFile(filePath) ? 7 : 30;
                var age = DateTime.UtcNow - cachedState.LastScanned;
                if (age.TotalDays < ttlDays)
                {
                    useCache = true;
                }
            }

            if (!useCache && !string.IsNullOrEmpty(_config.ApiKey))
            {
                // Enqueue for Cloud Scan
                _cloudQueue.Enqueue(filePath, hash);
                result.Details = "Verified Locally (Queued for Cloud check)";
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

        private static ScanResult PerformLocalScan(string filePath, string hash)
        {
            // 0. Specific Hash Check (EICAR)
            if (LocalScanner.IsEicarHash(hash))
            {
                return new ScanResult
                {
                    FilePath = filePath,
                    Status = ScanStatus.Threat,
                    ThreatType = ThreatType.Malware,
                    Details = "Critical: EICAR Test File Detected (Hash Match)"
                };
            }

            // A. Local Signatures
            var localMetadata = LocalScanner.CheckLocalSignatures(filePath);
            if (localMetadata.Status != ScanStatus.Safe)
            {
                return localMetadata;
            }

            // B. Byte Patterns & Entropy
            return LocalScanner.ScanFileContent(filePath);
        }

        private void HandleCloudResult(ScanResult result)
        {
            // If threat, take action immediately
            if (result.Status == ScanStatus.Threat)
            {
                MoveToQuarantine(result.FilePath, result.Details);
                OnThreatFound?.Invoke($"THREAT (Cloud): {Path.GetFileName(result.FilePath)} ({result.Details})");
            }
            
            // Notify UI
            OnScanCompleted?.Invoke(result);
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

        private static string ComputeSha256(string filePath)
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

        private static void MoveToQuarantine(string filePath, string reason)
        {
            try
            {
                string quarantineDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Quarantine");
                if (!Directory.Exists(quarantineDir)) Directory.CreateDirectory(quarantineDir);

                string fileName = Path.GetFileName(filePath);
                // Rename to .quarantine to prevent execution
                string newName = $"{Guid.NewGuid()}_{fileName}.quarantine";
                string destPath = Path.Combine(quarantineDir, newName);

                // Strategy: Move then Obfuscate (XOR) to avoid static detection of the file in quarantine
                File.Move(filePath, destPath);

                try 
                {
                    // Simple Obfuscation: XOR the first 4KB to break PE Header / Magic Numbers
                    // Key changed to random bytes (was DEADBEEF) to avoid heuristics
                    byte[] key = { 0x45, 0x8A, 0x21, 0x99 }; 
                    using (var fs = new FileStream(destPath, FileMode.Open, FileAccess.ReadWrite))
                    {
                        byte[] buffer = new byte[4096];
                        int bytesRead = fs.Read(buffer, 0, buffer.Length);
                        for (int i = 0; i < bytesRead; i++)
                        {
                            buffer[i] ^= key[i % key.Length];
                        }
                        fs.Position = 0;
                        fs.Write(buffer, 0, bytesRead);
                    }
                }
                catch { /* Ignore obfuscation errors, file is already moved and renamed */ }

                File.WriteAllText(destPath + ".txt", $"Original: {filePath}\nDate: {DateTime.Now}\nReason: {reason}\nNote: File is XOR obfuscated (Random Key)");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error moving to quarantine: {ex.Message}");
            }
        }
        private static bool IsCriticalFile(string filePath)
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
