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
            const string appName = "TruelSigth_SingleInstance";
            bool createdNew;

            _mutex = new Mutex(true, appName, out createdNew);

            if (!createdNew)
            {
                // Ya se está ejecutando -> Traer al frente
                IntPtr hWnd = FindWindow(null, "TruelSigth");
                if (hWnd != IntPtr.Zero)
                {
                    ShowWindow(hWnd, 9); // SW_RESTORE = 9
                    SetForegroundWindow(hWnd);
                }
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

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern IntPtr FindWindow(string? lpClassName, string lpWindowName);

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
        private static extern bool SetForegroundWindow(IntPtr hWnd);

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

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
