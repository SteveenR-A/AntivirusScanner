using System;
using System.Threading;
using System.Windows;

namespace AntivirusScanner
{
    public partial class App : System.Windows.Application
    {
        private Mutex? _mutex = null;
        private EventWaitHandle? _eventWaitHandle = null;
        private const string UniqueEventName = "Global\\TrueSight_Signal";
        private const string UniqueMutexName = "Global\\TrueSight_SingleInstance";

        protected override void OnStartup(StartupEventArgs e)
        {
            const string appName = UniqueMutexName;
            bool createdNew;

            _mutex = new Mutex(true, appName, out createdNew);

            if (!createdNew)
            {
                // Already running -> Signal the first instance
                try
                {
                    using (var eventHandle = EventWaitHandle.OpenExisting(UniqueEventName))
                    {
                        eventHandle.Set();
                    }
                }
                catch 
                { 
                    // Ignore if fail, maybe first instance is closing
                }
                
                Current.Shutdown();
                return;
            }
            
            // Init Signal Listener
            _eventWaitHandle = new EventWaitHandle(false, EventResetMode.AutoReset, UniqueEventName);
            Task.Run(() => 
            {
                while (true)
                {
                    _eventWaitHandle.WaitOne();
                    Dispatcher.Invoke(() => 
                    {
                        var mw = Current.MainWindow;
                        if (mw != null)
                        {
                            mw.Show();
                            if (mw.WindowState == WindowState.Minimized) 
                                mw.WindowState = WindowState.Normal;
                            mw.Activate();
                            mw.Topmost = true;  // Brief topmost to ensure visibility
                            mw.Topmost = false;
                        }
                    });
                }
            });

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
                _mutex.Dispose();
            }
            if (_eventWaitHandle != null)
            {
                _eventWaitHandle.Dispose();
            }
            base.OnExit(e);
        }
    }
}
