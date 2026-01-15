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
                    IncludeSubdirectories = true // Habilitado para producción
                };

                _watcher.Created += OnFileChanged;
                _watcher.Renamed += OnFileRenamed;
                // _watcher.Changed += OnFileChanged; 
                // Evitamos 'Changed' por ahora porque dispara muchos eventos duplicados al descargar

                _watcher.EnableRaisingEvents = true;
                IsRunning = true;
            }
            catch
            {
                // Silently fail or log to file in future
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
            // Usar un bucle de reintentos para esperar a que el archivo esté listo (desbloqueado)
            System.Threading.Tasks.Task.Run(async () => 
            {
                if (await WaitForFileReady(e.FullPath))
                {
                    _ = _scanner.ScanFile(e.FullPath);
                }
            });
        }

        private async System.Threading.Tasks.Task<bool> WaitForFileReady(string path)
        {
            int maxRetries = 20; // 10 segundos max (20 * 500ms)
            int delay = 500;

            for (int i = 0; i < maxRetries; i++)
            {
                try
                {
                    // Intenta abrir el archivo con acceso exclusivo
                    using (FileStream fs = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.None))
                    {
                        if (fs.Length > 0) return true; // Listo y con contenido
                    }
                }
                catch (IOException)
                {
                    // Archivo bloqueado (e.g., navegador descargando)
                }
                catch (Exception) 
                {
                    return false; // Error fatal (permisos, borrado, etc.)
                }

                await System.Threading.Tasks.Task.Delay(delay);
            }
            
            return false; // Timeout
        }

        public void Dispose()
        {
            Stop();
        }
    }
}
