using System;
using System.IO;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AntivirusScanner.Utils;

namespace AntivirusScanner.Core
{
    public class BackgroundMonitor : IDisposable
    {
        private FileSystemWatcher? _watcher;
        private Scanner _scanner;
        private AppConfig _config;

        private readonly ConcurrentDictionary<string, CancellationTokenSource> _debouncers = new();
        private readonly object _lock = new object();

        public bool IsRunning { get; private set; }

        public BackgroundMonitor(Scanner scanner, AppConfig config)
        {
            _scanner = scanner;
            _config = config;
        }

        public void Start()
        {
            if (IsRunning) return;
            if (string.IsNullOrEmpty(_config.TargetFolder) || !Directory.Exists(_config.TargetFolder)) return;

            try
            {
                _watcher = new FileSystemWatcher(_config.TargetFolder)
                {
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.LastWrite,
                    Filter = "*.*",
                    IncludeSubdirectories = true 
                };

                _watcher.Created += OnFileChanged;
                _watcher.Renamed += OnFileRenamed;
                _watcher.Changed += OnFileChanged; 

                _watcher.EnableRaisingEvents = true;
                IsRunning = true;
            }
            catch(Exception ex)
            {
                Console.WriteLine($"Error starting monitor: {ex.Message}");
            }
        }

        public void Stop()
        {
            if (_watcher != null)
            {
                _watcher.EnableRaisingEvents = false;
                _watcher.Dispose();
                _watcher = null;
            }
            IsRunning = false;
            
            // Cancel pending scans
            foreach(var src in _debouncers.Values) src.Cancel();
            _debouncers.Clear();
        }

        public void UpdateConfig(AppConfig newConfig)
        {
            bool wasRunning = IsRunning;
            Stop();
            _config = newConfig;
            if (wasRunning) Start();
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            QueueScan(e.FullPath);
        }

        private void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            QueueScan(e.FullPath);
        }

        private void QueueScan(string filePath)
        {
            lock (_lock)
            {
                // Cancel existing pending scan for this file (Debounce)
                if (_debouncers.TryRemove(filePath, out var existingCts))
                {
                    existingCts.Cancel();
                    existingCts.Dispose();
                }

                var cts = new CancellationTokenSource();
                _debouncers[filePath] = cts;

                // Start new background task
                Task.Run(async () => await ProcessWithDebounce(filePath, cts.Token), cts.Token);
            }
        }

        private async Task ProcessWithDebounce(string filePath, CancellationToken appToken)
        {
            try
            {
                // 1. Debounce Delay (Wait for bursts of 'Changed' events to stop, e.g. during download)
                await Task.Delay(1500, appToken);

                if (appToken.IsCancellationRequested) return;

                // 2. WaitForFileReady using Exponential Backoff
                if (await WaitForFileReady(filePath, appToken))
                {
                    if (appToken.IsCancellationRequested) return;
                    
                    // 3. Execute Scan
                    await _scanner.ScanFile(filePath);
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                Console.WriteLine($"Monitor Error: {ex.Message}");
            }
            finally
            {
                // Cleanup
                lock (_lock)
                {
                    if (_debouncers.TryGetValue(filePath, out var current) && current.Token == appToken)
                    {
                        _debouncers.TryRemove(filePath, out _);
                        current.Dispose();
                    }
                }
            }
        }

        private async Task<bool> WaitForFileReady(string path, CancellationToken token)
        {
            int maxRetries = 10; 
            int delay = 250; // Start with 250ms

            for (int i = 0; i < maxRetries; i++)
            {
                if (token.IsCancellationRequested) return false;

                try
                {
                    // Check if file still exists
                    if (!File.Exists(path)) return false;

                    // Try Exclusive Access
                    using (FileStream fs = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.None))
                    {
                        if (fs.Length > 0) return true; 
                    }
                }
                catch (IOException)
                {
                    // Locked
                }
                catch (Exception) 
                {
                    return false; 
                }

                // Exponential Backoff
                await Task.Delay(delay, token);
                delay *= 2; // Double delay: 250 -> 500 -> 1000 -> 2000 ...
            }
            
            return false; // Timeout
        }

        public void Dispose()
        {
            Stop();
        }
    }
}
