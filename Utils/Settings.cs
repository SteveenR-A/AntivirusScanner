using System;
using System.IO;
using System.Collections.Generic;
using System.Text.Json;
using Microsoft.Win32;

namespace AntivirusScanner.Utils
{
    public class AppConfig
    {
        public string TargetFolder { get; set; } = "";
        public string ApiKey { get; set; } = "";
        public bool StartOnBoot { get; set; } = false;
        public bool StartMinimized { get; set; } = false;

        public Dictionary<string, FileState> FileStates { get; set; } = new();
        public Dictionary<string, string> HashHistory { get; set; } = new();
    }

    public class FileState
    {
        public DateTime LastModified { get; set; }
        public long Size { get; set; }
        public string Hash { get; set; } = "";
        public string Status { get; set; } = "UNKNOWN"; // SAFE, THREAT, UNKNOWN
    }

    public static class SettingsManager
    {
        // %APPDATA%/AntivirusScanner/config.json
        private static readonly string ConfigDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), 
            "AntivirusScanner"
        );
        private static readonly string ConfigFile = Path.Combine(ConfigDir, "config.json");
        private const string RegistryKeyName = "AntivirusScannerV2";

        public static AppConfig Load()
        {
            AppConfig config = new AppConfig();
            if (File.Exists(ConfigFile))
            {
                try
                {
                    string json = File.ReadAllText(ConfigFile);
                    config = JsonSerializer.Deserialize<AppConfig>(json) ?? new AppConfig();
                }
                catch { }
            }
            
            // Sync registry state
            config.StartOnBoot = IsAutoStartEnabled();
            return config;
        }

        public static void Save(AppConfig config)
        {
            try
            {
                if (!Directory.Exists(ConfigDir)) Directory.CreateDirectory(ConfigDir);
                
                string json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(ConfigFile, json);

                // Update Registry
                SetAutoStart(config.StartOnBoot);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error guardando configuración: {ex.Message}");
            }
        }

        private static bool IsAutoStartEnabled()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", false);
                return key?.GetValue(RegistryKeyName) != null;
            }
            catch { return false; }
        }

        private static void SetAutoStart(bool enable)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true);
                if (key == null) return;

                if (enable)
                {
                    string location = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
                    if (!string.IsNullOrEmpty(location))
                    {
                        // Add /minimized arg if needed later, for now just the exe
                        key.SetValue(RegistryKeyName, $"\"{location}\" /minimized"); 
                    }
                }
                else
                {
                    key.DeleteValue(RegistryKeyName, false);
                }
            }
            catch { }
        }
    }
}
