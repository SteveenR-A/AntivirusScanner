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
                    await ProcessSingleRequest(request);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"CloudQueue Loop Error: {ex.Message}");
            }
            finally
            {
                _isRunning = false;
                EnsureQueueProcessing();
            }
        }

        private void EnsureQueueProcessing() 
        {
            if (!_queue.IsEmpty)
            {
                _isRunning = true;
                _ = Task.Run(ProcessQueueLoop);
            }
        }

        private async Task ProcessSingleRequest(ScanRequest request)
        {
            // 1. Check Daily Quota
            if (_config.DailyApiUsage >= 500)
            {
                NotifySkipped(request, "Daily Quota Exceeded (500/500)");
                return;
            }

            // 2. Call VirusTotal
            var (detections, engines) = await _vtService.CheckFileHashAsync(request.Hash, _config);

            // 3. Create & Analyze Result
            var result = CreateScanResult(request, detections, engines);

            // 4. Handle Blacklist & Cache
            if (result.Status == ScanStatus.Threat)
            {
                AddToBlacklist(request.Hash);
            }
            else if (result.Status == ScanStatus.Safe)
            {
                UpdateLocalCache(request.FilePath, request.Hash);
            }

             // 5. Check for Quota Exhaustion during call (Edge case)
            if (detections == -2)
            {
                 result.Status = ScanStatus.Skipped;
                 result.Details = "Daily Quota Exceeded (500/500)";
            }

            // 6. Notify UI & Save
            OnCloudResult?.Invoke(result);
            SettingsManager.Save(_config);
        }

        private void NotifySkipped(ScanRequest request, string reason)
        {
             var result = new ScanResult 
             { 
                 FilePath = request.FilePath, 
                 Status = ScanStatus.Skipped,
                 Details = reason
             };
             OnCloudResult?.Invoke(result);
        }

        private void AddToBlacklist(string hash)
        {
            lock (_config.BlacklistedHashes)
            {
                _config.BlacklistedHashes.Add(hash);
            }
        }

        private ScanResult CreateScanResult(ScanRequest request, int detections, System.Collections.Generic.List<string>? engines)
        {
            var result = new ScanResult { FilePath = request.FilePath };

            if (detections == -1) // Error
            {
                result.Status = ScanStatus.Error;
                result.Details = "VirusTotal Scan Failed";
                return result;
            }
            
            if (detections == -2) return result; // Handled in caller

            if (detections == 0)
            {
                result.Status = ScanStatus.Safe;
                result.Details = "Verified Safe by VirusTotal";
                return result;
            }

            // Suspicious or Threat
            return AnalyzeDetections(result, detections, engines);
        }

        private ScanResult AnalyzeDetections(ScanResult result, int detections, System.Collections.Generic.List<string>? engines)
        {
            // VIP Club Logic
            var vipVendors = new[] { "Microsoft", "Kaspersky", "Google", "ESET-NOD32", "BitDefender", "Symantec" };
            bool vipConfirmed = engines != null && engines.Any(e => vipVendors.Contains(e));

            if (detections >= 4 || vipConfirmed)
            {
                result.Status = ScanStatus.Threat;
                result.ThreatType = ThreatType.Malware;
                string vipTag = vipConfirmed ? "[VIP CONFIRMED]" : "";
                result.Details = $"VirusTotal: {detections} detections {vipTag}";
            }
            else
            {
                // 1-3 detections AND No VIPs
                result.Status = ScanStatus.Suspicious;
                result.ThreatType = ThreatType.Unknown;
                result.Details = $"VirusTotal: {detections} flag(s) (No Big Vendor confirmed). Treating as Suspicious.";
            }

            return result;
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
