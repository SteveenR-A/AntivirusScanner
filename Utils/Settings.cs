using System;
using System.IO;
using System.Collections.Generic;
using System.Text.Json;
using Microsoft.Win32;
using System.Security.Cryptography;

namespace AntivirusScanner.Utils
{
    public class AppConfig
    {
        public string TargetFolder { get; set; } = "";
        [System.Text.Json.Serialization.JsonIgnore]
        public string ApiKey { get; set; } = "";
        public bool StartOnBoot { get; set; } = false;
        public bool StartMinimized { get; set; } = false;
        public bool MonitoringEnabled { get; set; } = true;

        public string EncryptedApiKey { get; set; } = ""; // Ciphertext stored in JSON

        public Dictionary<string, FileState> FileStates { get; set; } = new();
        public Dictionary<string, string> HashHistory { get; set; } = new();
    }

    public class FileState
    {
        public DateTime LastModified { get; set; }
        public long Size { get; set; }
        public string Hash { get; set; } = "";
        public string Status { get; set; } = ""; // SAFE, THREAT, UNKNOWN
    }

    public static class SettingsManager
    {
        // %APPDATA%/TrueSight/config.json
        private static readonly string ConfigDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), 
            "TrueSight"
        );
        private static readonly string ConfigFile = Path.Combine(ConfigDir, "config.json");
        private const string RegistryKeyName = "TrueSight";

        public static AppConfig Load()
        {
            AppConfig config = new AppConfig();
            try
            {
                if (File.Exists(ConfigFile))
                {
                    string json = File.ReadAllText(ConfigFile);
                    config = JsonSerializer.Deserialize<AppConfig>(json) ?? new AppConfig();
                }
                
                // Decrypt API Key
                if (!string.IsNullOrEmpty(config.EncryptedApiKey))
                {
                    config.ApiKey = Unprotect(config.EncryptedApiKey);
                }
            }
            catch { }
            
            // Sync registry state
            config.StartOnBoot = IsAutoStartEnabled();
            
            // Set Default Folder if empty (First Run)
            if (string.IsNullOrEmpty(config.TargetFolder))
            {
                config.TargetFolder = PathHelper.GetDownloadsFolder();
            }

            return config;
        }

        public static void Save(AppConfig config)
        {
            try
            {
                if (!Directory.Exists(ConfigDir)) Directory.CreateDirectory(ConfigDir);
                
                // Encrypt API Key before saving
                if (!string.IsNullOrEmpty(config.ApiKey))
                {
                    config.EncryptedApiKey = Protect(config.ApiKey);
                }
                else
                {
                    config.EncryptedApiKey = "";
                }

                string json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(ConfigFile, json);

                SetAutoStart(config.StartOnBoot);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error guardando configuración: {ex.Message}");
            }
        }
        
        // --- DPAPI Helpers ---
        private static string Protect(string plainText)
        {
            try 
            {
                byte[] data = System.Text.Encoding.UTF8.GetBytes(plainText);
                byte[] encrypted = ProtectedData.Protect(data, null, DataProtectionScope.CurrentUser);
                return Convert.ToBase64String(encrypted);
            }
            catch { return ""; }
        }

        private static string Unprotect(string cipherText)
        {
            try 
            {
                byte[] data = Convert.FromBase64String(cipherText);
                byte[] decrypted = ProtectedData.Unprotect(data, null, DataProtectionScope.CurrentUser);
                return System.Text.Encoding.UTF8.GetString(decrypted);
            }
            catch { return ""; }
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
                    string? location = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
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
