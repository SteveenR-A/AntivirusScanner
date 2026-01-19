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
            try
            {
                // Tray Icon from Exe
                var exePath = Environment.ProcessPath;
                if (!string.IsNullOrEmpty(exePath))
                {
                    _notifyIcon.Icon = System.Drawing.Icon.ExtractAssociatedIcon(exePath);
                }
                else 
                {
                    throw new Exception("Cannot determine exe path");
                }
                
                // Window Icon from Resource (Safe Load)
                this.Icon = System.Windows.Media.Imaging.BitmapFrame.Create(new Uri("pack://application:,,,/logo.png"));
            }
            catch
            {
                // Fallback icon if extraction fails
                _notifyIcon.Icon = System.Drawing.SystemIcons.Shield; 
            }
            
            _notifyIcon.Visible = true;
            _notifyIcon.Text = "TrueSight - Protected";
            _notifyIcon.DoubleClick += (s, args) => ShowWindow();
            
            var contextMenu = new System.Windows.Forms.ContextMenuStrip();
            contextMenu.Items.Add("Open", null, (s, e) => ShowWindow());
            contextMenu.Items.Add("Exit", null, (s, e) => FullExit());
            _notifyIcon.ContextMenuStrip = contextMenu;

            // Load logic with Safe Fallback
            try {
                _config = SettingsManager.Load();
            } catch (Exception ex) {
                MessageBox.Show($"Error loading config: {ex.Message}\nUsing defaults.", "TrueSight", MessageBoxButton.OK, MessageBoxImage.Warning);
                _config = new AppConfig(); // Fallback
            }
            _scanner = new Scanner(_config);
            _monitor = new BackgroundMonitor(_scanner, _config);

            // Bind Scanner Events
            _scanner.OnThreatFound += msg => 
            {
                Dispatcher.Invoke(() => {
                   LogActivity($"🚨 {msg}");
                   ListHistory.Items.Insert(0, $"{DateTime.Now}: {msg}");
                   _notifyIcon.ShowBalloonTip(3000, "THREAT DETECTED", msg, System.Windows.Forms.ToolTipIcon.Warning);
                });
            };

            _scanner.OnScanCompleted += result =>
            {
                 Dispatcher.Invoke(() => {
                     if (!result.IsSafe && result.Status != ScanStatus.Skipped)
                     {
                         // Already logged by threat found
                     }
                     else if (result.Status != ScanStatus.Skipped)
                     {
                         LogActivity($"✅ Scanned: {System.IO.Path.GetFileName(result.FilePath)} (Safe)");
                     }
                     TxtLastScan.Text = $"Last scan: {DateTime.Now.ToShortTimeString()}";
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
            if (_config.MonitoringEnabled)
            {
                if (!_monitor.Start()) 
                {
                    _config.MonitoringEnabled = false; // Disable if failed
                    SettingsManager.Save(_config);
                }
            }
            UpdateMonitorUI();
        }

        private void UpdateMonitorUI()
        {
            if (_monitor.IsRunning)
            {
                ToggleMonitor.Content = "ON";
                ToggleMonitor.IsChecked = true;
                TxtStatusSidebar.Text = "🟢 Protected";
                TxtStatusSidebar.Foreground = System.Windows.Media.Brushes.Lime;
            }
            else
            {
                ToggleMonitor.Content = "OFF";
                ToggleMonitor.IsChecked = false;
                TxtStatusSidebar.Text = "⚠️ Stopped";
                TxtStatusSidebar.Foreground = System.Windows.Media.Brushes.Yellow;
            }
        }

        private void ToggleMonitor_Click(object sender, RoutedEventArgs e)
        {
            if (_monitor.IsRunning)
            {
                _monitor.Stop();
                _config.MonitoringEnabled = false;
            }
            else
            {
                if (_monitor.Start())
                {
                    _config.MonitoringEnabled = true;
                }
                else
                {
                    MessageBox.Show("Could not start monitor.\nCheck if Target Folder exists.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    _config.MonitoringEnabled = false;
                    ToggleMonitor.IsChecked = false; // Visual revert
                    return; // Abort save/update
                }
            }
            SettingsManager.Save(_config);
            UpdateMonitorUI();
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



        protected override void OnClosing(CancelEventArgs e)
        {
            if (_monitor.IsRunning)
            {
                e.Cancel = true; // Don't close
                Hide(); // Just hide to tray
                _notifyIcon.ShowBalloonTip(2000, "TrueSight", "Antivirus is running in background.", System.Windows.Forms.ToolTipIcon.Info);
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

        private void ShowSettings()
        {
            ViewDashboard.Visibility = Visibility.Collapsed;
            ViewSettings.Visibility = Visibility.Visible;
            ViewHistory.Visibility = Visibility.Collapsed;
        }

        private void BtnSettings_Click(object sender, RoutedEventArgs e)
        {
            ShowSettings();
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
            
            MessageBox.Show("Settings saved.", "TrueSight", MessageBoxButton.OK, MessageBoxImage.Information);
            ShowDashboard();
        }

        private async void BtnScanNow_Click(object sender, RoutedEventArgs e)
        {
            // Check for API Key
            if (string.IsNullOrEmpty(_config.ApiKey))
            {
                var result = MessageBox.Show(
                    "You have not configured a VirusTotal API Key. \n\n" +
                    "Without it, the scanner will use local signatures only and be less effective.\n" +
                    "Do you want to go to Settings to add one now?\n\n" +
                    "(Select 'No' to scan anyway)",
                    "Security Recommendation",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);

                if (result == MessageBoxResult.Yes)
                {
                    ShowSettings(); // Switch to settings view
                    return;
                }
            }

            var btn = (Button)sender;
            btn.IsEnabled = false;
            btn.Content = "Scanning...";
            
            LogActivity("⏳ Starting full scan...");
            await System.Threading.Tasks.Task.Run(() => _scanner.RunFullScan());
            
            btn.Content = "SCAN ALL NOW";
            btn.IsEnabled = true;
            LogActivity("🏁 Full scan completed.");
        }

        private void ShowDashboard()
        {
            ViewDashboard.Visibility = Visibility.Visible;
            ViewSettings.Visibility = Visibility.Collapsed;
            ViewHistory.Visibility = Visibility.Collapsed;
        }



        private void LogActivity(string text)
        {
            TxtRecentLog.Text = text + "\n" + TxtRecentLog.Text;
            if (TxtRecentLog.Text.Length > 500) TxtRecentLog.Text = TxtRecentLog.Text.Substring(0, 500);
        }
    }
}
