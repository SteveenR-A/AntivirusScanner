using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;

namespace AntivirusScanner.UI
{
    public class ConfigWindow : Window
    {
        private TextBox _apiKeyBox;
        private TextBox _folderBox;
        public string ResultApiKey { get; private set; } = "";
        public string ResultFolder { get; private set; } = "";
        public bool IsSaved { get; private set; } = false;

        public ConfigWindow(string currentApiKey, string currentFolder)
        {
            Title = "Configuración Antivirus";
            Width = 500;
            Height = 350;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            ResizeMode = ResizeMode.NoResize;
            Background = new SolidColorBrush(Color.FromRgb(30, 30, 30)); // Dark Mode
            Foreground = Brushes.White;

            var mainStack = new StackPanel { Margin = new Thickness(20) };

            // Header
            mainStack.Children.Add(new TextBlock 
            { 
                Text = "Configuración Inicial", 
                FontSize = 20, 
                FontWeight = FontWeights.Bold, 
                Margin = new Thickness(0, 0, 0, 20),
                Foreground = Brushes.White
            });

            // API Key Section
            mainStack.Children.Add(new TextBlock { Text = "VirusTotal API Key:", Foreground = Brushes.LightGray });
            _apiKeyBox = new TextBox 
            { 
                Text = currentApiKey, 
                Margin = new Thickness(0, 5, 0, 15), 
                Padding = new Thickness(5),
                Background = new SolidColorBrush(Color.FromRgb(50, 50, 50)),
                Foreground = Brushes.White,
                BorderThickness = new Thickness(1),
                BorderBrush = Brushes.Gray
            };
            mainStack.Children.Add(_apiKeyBox);

            // Folder Section
            mainStack.Children.Add(new TextBlock { Text = "Carpeta a Escanear:", Foreground = Brushes.LightGray });
            
            var folderGrid = new Grid { Margin = new Thickness(0, 5, 0, 20) };
            folderGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            folderGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            _folderBox = new TextBox 
            { 
                Text = currentFolder, 
                Padding = new Thickness(5), 
                IsReadOnly = true,
                Background = new SolidColorBrush(Color.FromRgb(50, 50, 50)),
                Foreground = Brushes.White,
                BorderThickness = new Thickness(1),
                BorderBrush = Brushes.Gray
            };
            Grid.SetColumn(_folderBox, 0);

            var browseBtn = new Button 
            { 
                Content = "...", 
                Width = 40, 
                Margin = new Thickness(10, 0, 0, 0),
                Background = new SolidColorBrush(Color.FromRgb(60, 60, 60)),
                Foreground = Brushes.White
            };
            browseBtn.Click += BrowseBtn_Click;
            Grid.SetColumn(browseBtn, 1);

            folderGrid.Children.Add(_folderBox);
            folderGrid.Children.Add(browseBtn);
            mainStack.Children.Add(folderGrid);

            // Save Button
            var saveBtn = new Button 
            { 
                Content = "Guardar y Continuar", 
                Height = 40, 
                Margin = new Thickness(0, 20, 0, 0),
                Background = new SolidColorBrush(Color.FromRgb(0, 122, 204)), // VS Blue
                Foreground = Brushes.White,
                FontWeight = FontWeights.Bold,
                BorderThickness = new Thickness(0)
            };
            saveBtn.Click += SaveBtn_Click;
            mainStack.Children.Add(saveBtn);

            Content = mainStack;
        }

        private void BrowseBtn_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFolderDialog
            {
                Title = "Seleccionar carpeta de descargas",
                InitialDirectory = string.IsNullOrWhiteSpace(_folderBox.Text) ? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) : _folderBox.Text
            };

            if (dialog.ShowDialog() == true)
            {
                _folderBox.Text = dialog.FolderName;
            }
        }

        private void SaveBtn_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(_apiKeyBox.Text))
            {
                MessageBox.Show("La API Key es obligatoria.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            if (string.IsNullOrWhiteSpace(_folderBox.Text))
            {
                MessageBox.Show("Debes seleccionar una carpeta.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            ResultApiKey = _apiKeyBox.Text.Trim();
            ResultFolder = _folderBox.Text.Trim();
            IsSaved = true;
            Close();
        }
    }
}
