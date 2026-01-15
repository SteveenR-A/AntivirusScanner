using System;
using System.Windows;
using System.Windows.Controls;
using System.Collections.ObjectModel;
using AntivirusScanner.Core;
using AntivirusScanner.Utils;
using System.ComponentModel;
// Aliases to resolve conflicts with System.Windows.Forms
using Button = System.Windows.Controls.Button;
using Application = System.Windows.Application;
using MessageBox = System.Windows.MessageBox;

namespace AntivirusScanner.UI
{
    public partial class MainWindow : Window
    {
        private AppConfig _config;
        private Scanner _scanner;
        private BackgroundMonitor _monitor;
        private System.Windows.Forms.NotifyIcon _notifyIcon;

        public MainWindow()
        {
            InitializeComponent();
            
            // Setup Tray Icon
            _notifyIcon = new System.Windows.Forms.NotifyIcon();
            _notifyIcon.Icon = System.Drawing.Icon.ExtractAssociatedIcon(System.Reflection.Assembly.GetExecutingAssembly().Location);
            _notifyIcon.Visible = true;
            _notifyIcon.Text = "Steveen Antivirus - Protegido";
            _notifyIcon.DoubleClick += (s, args) => ShowWindow();
            
            var contextMenu = new System.Windows.Forms.ContextMenuStrip();
            contextMenu.Items.Add("Abrir", null, (s, e) => ShowWindow());
            contextMenu.Items.Add("Salir", null, (s, e) => FullExit());
            _notifyIcon.ContextMenuStrip = contextMenu;

            // Load logic
            _config = SettingsManager.Load();
            _scanner = new Scanner(_config);
            _monitor = new BackgroundMonitor(_scanner, _config);

            // Bind Scanner Events
            _scanner.OnThreatFound += msg => 
            {
                Dispatcher.Invoke(() => {
                   LogActivity($"🚨 {msg}");
                   ListHistory.Items.Insert(0, $"{DateTime.Now}: {msg}");
                   _notifyIcon.ShowBalloonTip(3000, "AMENAZA DETECTADA", msg, System.Windows.Forms.ToolTipIcon.Warning);
                });
            };

            _scanner.OnScanCompleted += result =>
            {
                 Dispatcher.Invoke(() => {
                     if (!result.IsSafe && !result.IsSkipped)
                     {
                         // Already logged by threat found
                     }
                     else if (!result.IsSkipped)
                     {
                         LogActivity($"✅ Analizado: {System.IO.Path.GetFileName(result.FilePath)} (Seguro)");
                     }
                     TxtLastScan.Text = $"Último análisis: {DateTime.Now.ToShortTimeString()}";
                 });
            };

            LoadSettingsToUI();
            StartServices();

            // Check Minimized Start
            string[] args = Environment.GetCommandLineArgs();
            bool startMin = _config.StartMinimized;
            foreach(var arg in args) if(arg.Contains("/minimized")) startMin = true;

            if (startMin)
            {
                Hide();
            }
        }

        private void StartServices()
        {
            if (_config.StartOnBoot) // Reuse this flag logic or just always start monitor? usually always
            {
                _monitor.Start();
                ToggleMonitor.IsChecked = true;
            }
            else
            {
                ToggleMonitor.IsChecked = false;
            }
            ToggleMonitor.Content = _monitor.IsRunning ? "ON" : "OFF";
        }

        private void LoadSettingsToUI()
        {
            InputApiKey.Password = _config.ApiKey;
            InputFolder.Text = _config.TargetFolder;
            CheckStartOnBoot.IsChecked = _config.StartOnBoot;
            CheckStartMinimized.IsChecked = _config.StartMinimized;
        }

        // --- UI Interactions ---

        private void ShowWindow()
        {
            Show();
            WindowState = WindowState.Normal;
            Activate();
        }

        private void FullExit()
        {
            _notifyIcon.Dispose();
            _monitor.Stop();
            Application.Current.Shutdown();
        }

        protected override void OnStateChanged(EventArgs e)
        {
            if (WindowState == WindowState.Minimized)
            {
                Hide(); // Send to tray
            }
            base.OnStateChanged(e);
        }

        protected override void OnClosing(CancelEventArgs e)
        {
            if (_monitor.IsRunning)
            {
                e.Cancel = true; // Don't close
                Hide(); // Just hide to tray
                _notifyIcon.ShowBalloonTip(2000, "Steveen AV", "El antivirus sigue corriendo en segundo plano.", System.Windows.Forms.ToolTipIcon.Info);
            }
            else
            {
                // Protection OFF -> Full Exit
                _notifyIcon.Dispose();
                _monitor.Stop();
                // Window closes, App shuts down
            }
        }



        private void BtnDashboard_Click(object sender, RoutedEventArgs e)
        {
            ViewDashboard.Visibility = Visibility.Visible;
            ViewSettings.Visibility = Visibility.Collapsed;
            ViewHistory.Visibility = Visibility.Collapsed;
        }

        private void BtnSettings_Click(object sender, RoutedEventArgs e)
        {
            ViewDashboard.Visibility = Visibility.Collapsed;
            ViewSettings.Visibility = Visibility.Visible;
            ViewHistory.Visibility = Visibility.Collapsed;
        }

        private void BtnHistory_Click(object sender, RoutedEventArgs e)
        {
            ViewDashboard.Visibility = Visibility.Collapsed;
            ViewSettings.Visibility = Visibility.Collapsed;
            ViewHistory.Visibility = Visibility.Visible;
        }

        private void BtnSaveSettings_Click(object sender, RoutedEventArgs e)
        {
            _config.ApiKey = InputApiKey.Password;
            _config.TargetFolder = InputFolder.Text;
            _config.StartOnBoot = CheckStartOnBoot.IsChecked == true;
            _config.StartMinimized = CheckStartMinimized.IsChecked == true;

            SettingsManager.Save(_config);
            _scanner.UpdateConfig(_config);
            _monitor.UpdateConfig(_config);
            
            MessageBox.Show("Configuración guardada.", "Steveen AV", MessageBoxButton.OK, MessageBoxImage.Information);
            BtnDashboard_Click(null, null);
        }

        private async void BtnScanNow_Click(object sender, RoutedEventArgs e)
        {
            var btn = (Button)sender;
            btn.IsEnabled = false;
            btn.Content = "Analizando...";
            
            LogActivity("⏳ Iniciando escaneo completo...");
            await System.Threading.Tasks.Task.Run(() => _scanner.RunFullScan());
            
            btn.Content = "ESCANEAR TODO AHORA";
            btn.IsEnabled = true;
            LogActivity("🏁 Escaneo completo finalizado.");
        }

        private void ToggleMonitor_Click(object sender, RoutedEventArgs e)
        {
            if (_monitor.IsRunning)
            {
                _monitor.Stop();
                ToggleMonitor.Content = "OFF";
                TxtStatusSidebar.Text = "⚠️ Detenido";
                TxtStatusSidebar.Foreground = System.Windows.Media.Brushes.Yellow;
            }
            else
            {
                _monitor.Start();
                ToggleMonitor.Content = "ON";
                TxtStatusSidebar.Text = "🟢 Protegido";
                TxtStatusSidebar.Foreground = System.Windows.Media.Brushes.Lime;
            }
        }

        private void LogActivity(string text)
        {
            TxtRecentLog.Text = text + "\n" + TxtRecentLog.Text;
            if (TxtRecentLog.Text.Length > 500) TxtRecentLog.Text = TxtRecentLog.Text.Substring(0, 500);
        }
    }
}
