using System;
using System.IO;
using AntivirusScanner.Utils;

namespace AntivirusScanner.Core
{
    public class BackgroundMonitor : IDisposable
    {
        private FileSystemWatcher? _watcher;
        private Scanner _scanner;
        private AppConfig _config;

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
                    IncludeSubdirectories = false // Por ahora false, como pidió original
                };

                _watcher.Created += OnFileChanged;
                _watcher.Renamed += OnFileRenamed;
                // _watcher.Changed += OnFileChanged; 
                // Evitamos 'Changed' por ahora porque dispara muchos eventos duplicados al descargar

                _watcher.EnableRaisingEvents = true;
                IsRunning = true;
                Console.WriteLine($"[Monitor] Vigilando: {_config.TargetFolder}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Monitor] Error iniciando: {ex.Message}");
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
            // Escanear el nuevo nombre
            _ = _scanner.ScanFile(e.FullPath);
        }

        private void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            // Pequeño delay para permitir que el archivo termine de copiarse/crearse
            System.Threading.Tasks.Task.Delay(500).ContinueWith(_ => 
            {
                _ = _scanner.ScanFile(e.FullPath);
            });
        }

        public void Dispose()
        {
            Stop();
        }
    }
}
