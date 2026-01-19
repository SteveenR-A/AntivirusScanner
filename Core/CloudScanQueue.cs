using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Linq;
using AntivirusScanner.Utils;

namespace AntivirusScanner.Core
{
    public class CloudScanQueue
    {
        // Safe Queue for threads (Files accumulate here)
        private readonly ConcurrentQueue<ScanRequest> _queue = new();
        private readonly VirusTotalService _vtService;
        private readonly AppConfig _config;
        private bool _isRunning = false;

        // Event to notify UI when a cloud file is processed
        public event Action<ScanResult>? OnCloudResult;

        public CloudScanQueue(AppConfig config)
        {
            _config = config;
            _vtService = new VirusTotalService();
        }

        // Method 1: Add to Queue (The Producer)
        // Scanner and Monitor call this. Does NOT block, returns immediately.
        public void Enqueue(string filePath, string hash)
        {
            _queue.Enqueue(new ScanRequest { FilePath = filePath, Hash = hash });
            
            // Ensure the processor is running
            if (!_isRunning)
            {
                _isRunning = true;
                Task.Run(ProcessQueueLoop);
            }
        }

        // Method 2: The Infinite Loop (The Consumer)
        private async Task ProcessQueueLoop()
        {
            try
            {
                while (_queue.TryDequeue(out var request))
                {
                    // 1. Check Daily Quota before spending time
                    if (_config.DailyApiUsage >= 500) 
                    {
                        var skippedResult = new ScanResult 
                        { 
                            FilePath = request.FilePath, 
                            Status = ScanStatus.Skipped,
                            Details = "Daily Quota Exceeded (500/500)"
                        };
                        OnCloudResult?.Invoke(skippedResult);
                        continue; 
                    }

                    // 2. Call VirusTotal (This takes time and manages 15s delay internally)
                    // We need to pass _config to CheckFileHashAsync as per existing implementation
                    // Returns (Count, List<string>? Engines)
                    var (detections, engines) = await _vtService.CheckFileHashAsync(request.Hash, _config);

                    // 3. Create Result
                    var result = new ScanResult { FilePath = request.FilePath };
                    
                    if (detections == -2) 
                    {
                         // Quota exhausted during call
                         result.Status = ScanStatus.Skipped;
                         result.Details = "Daily Quota Exceeded (500/500)";
                    }
                    else if (detections > 0)
                    {
                        // VIP Club Logic: Check if any major vendor is present
                        var vipVendors = new[] { "Microsoft", "Kaspersky", "Google", "ESET-NOD32", "BitDefender", "Symantec" };
                        bool vipConfirmed = engines != null && engines.Any(e => vipVendors.Contains(e)); // Simple contains check, might need better matching if names vary

                        if (detections >= 4 || vipConfirmed)
                        {
                            result.Status = ScanStatus.Threat;
                            result.ThreatType = ThreatType.Malware;
                            string vipTag = vipConfirmed ? "[VIP CONFIRMED]" : "";
                            result.Details = $"VirusTotal: {detections} detections {vipTag}";
                            
                            // Add to blacklist (Quarantine Trigger)
                            lock(_config.BlacklistedHashes)
                            {
                                _config.BlacklistedHashes.Add(request.Hash);
                            }
                        }
                        else
                        {
                             // 1-3 detections AND No VIPs -> Suspicious (False Positive Candidate)
                             result.Status = ScanStatus.Suspicious;
                             result.ThreatType = ThreatType.Unknown;
                             result.Details = $"VirusTotal: {detections} flag(s) (No Big Vendor confirmed). Treating as Suspicious.";
                             // Do NOT blacklist automatically.
                        }
                    }
                    else if (detections == 0)
                    {
                        result.Status = ScanStatus.Safe;
                        result.Details = "Verified Safe by VirusTotal";
                        // Update Local Cache
                        UpdateLocalCache(request.FilePath, request.Hash);
                    }
                    else 
                    {
                        // Error case (-1)
                        result.Status = ScanStatus.Error;
                        result.Details = "VirusTotal Scan Failed";
                    }

                    // 4. Notify UI (Important because this happens asynchronously)
                    OnCloudResult?.Invoke(result);
                    
                    // Save config (API counter)
                    // Locking not strictly necessary for simple types but good practice if multiple threads were writing
                    // However, Scanner also writes. SettingsManager.Save might need care.
                    // For now, we follow existing pattern.
                    SettingsManager.Save(_config);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"CloudQueue Loop Error: {ex.Message}");
            }
            finally
            {
                _isRunning = false;
                // Double check if queue has items (race condition where item added just closely after loop exit)
                if (!_queue.IsEmpty)
                {
                    _isRunning = true;
                    _ = Task.Run(ProcessQueueLoop);
                }
            }
        }

        private void UpdateLocalCache(string path, string hash)
        {
            try 
            {
                // We need file info for cache
                var fileInfo = new System.IO.FileInfo(path);
                if (fileInfo.Exists)
                {
                    lock (_config.FileStates)
                    {
                        _config.FileStates[path] = new FileState 
                        { 
                            LastModified = fileInfo.LastWriteTimeUtc, 
                            Size = fileInfo.Length, 
                            Hash = hash,
                            Status = ScanStatus.Safe.ToString(),
                            LastScanned = DateTime.UtcNow 
                        };
                    }
                    
                    lock (_config.HashHistory)
                    {
                         _config.HashHistory[hash] = ScanStatus.Safe.ToString();
                    }
                }
            }
            catch(Exception ex)
            {
                Debug.WriteLine($"Failed to update cache: {ex.Message}");
            }
        }

        private sealed class ScanRequest 
        { 
            public string FilePath { get; set; } = ""; 
            public string Hash { get; set; } = ""; 
        }
    }
}
