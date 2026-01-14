using System;
using System.IO;
using System.Threading;
using System.Windows; // WPF Not needed for Console.WriteLine, but for Application
using AntivirusScanner.Core;
using AntivirusScanner.UI;
using AntivirusScanner.Utils;

namespace AntivirusScanner
{
    class Program
    {
        [STAThread] // Requerido para componentes COM/WPF
        static void Main(string[] args)
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            Console.WriteLine("🛡️  AntivirusScanner v2.0 (C# Edition)");
            Console.WriteLine("--------------------------------------");

            // 1. Cargar Configuración
            var config = SettingsManager.Load();

            // 2. Validar o Detectar valores por defecto
            if (string.IsNullOrEmpty(config.TargetFolder))
            {
                config.TargetFolder = PathHelper.GetDownloadsFolder();
            }

            bool needsConfig = string.IsNullOrEmpty(config.ApiKey) || !Directory.Exists(config.TargetFolder);

            // 3. Si falta configuración, lanzar GUI
            if (needsConfig)
            {
                Console.WriteLine("ℹ️  Falta configuración (API Key o Carpeta). Abriendo ventana...");
                
                // Iniciar WPF App context para mostrar la ventana
                var app = new Application();
                var window = new ConfigWindow(config.ApiKey, config.TargetFolder);
                
                app.Run(window); // Bloquea hasta que se cierra la ventana

                if (window.IsSaved)
                {
                    config.ApiKey = window.ResultApiKey;
                    config.TargetFolder = window.ResultFolder;
                    SettingsManager.Save(config);
                    Console.WriteLine("✅ Configuración guardada.");
                }
                else
                {
                    Console.WriteLine("❌ Cancelado por el usuario.");
                    return;
                }
            }

            // 4. Ejecutar Escáner
            if (string.IsNullOrEmpty(config.ApiKey))
            {
                Console.WriteLine("⚠️  Aviso: Sin API Key, el análisis será limitado (solo firmas locales).");
            }

            var scanner = new Scanner(config);
            // Ejecutar en hilo asíncrono y esperar
            scanner.RunScan().GetAwaiter().GetResult();

            Console.WriteLine("\nPresiona Enter para salir...");
            Console.ReadLine();
        }
    }
}
