using System;
using System.Threading;
using System.Windows;

namespace AntivirusScanner
{
    public partial class App : System.Windows.Application
    {
        private static Mutex? _mutex = null;

        protected override void OnStartup(StartupEventArgs e)
        {
            const string appName = "AntivirusScannerV2_SingleInstance";
            bool createdNew;

            _mutex = new Mutex(true, appName, out createdNew);

            if (!createdNew)
            {
                // Ya se está ejecutando
                System.Windows.MessageBox.Show("La aplicación ya se está ejecutando.", "Antivirus Scanner", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
                Current.Shutdown();
                return;
            }

            base.OnStartup(e);

            // Global Error Handling
            this.DispatcherUnhandledException += (s, args) =>
            {
                System.Windows.MessageBox.Show($"Ocurrió un error inesperado:\n{args.Exception.Message}\n\n{args.Exception.StackTrace}", "Error Crítico", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
                args.Handled = true;
            };
        }

        protected override void OnExit(ExitEventArgs e)
        {
            if (_mutex != null)
            {
                _mutex.ReleaseMutex();
            }
            base.OnExit(e);
        }
    }
}
