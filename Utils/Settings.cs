using System;
using System.IO;
using System.Text.Json;

namespace AntivirusScanner.Utils
{
    public class AppConfig
    {
        public string TargetFolder { get; set; } = "";
        public string ApiKey { get; set; } = "";
        public Dictionary<string, FileState> FileStates { get; set; } = new();
        public Dictionary<string, string> HashHistory { get; set; } = new();
    }

    public class FileState
    {
        public DateTime LastModified { get; set; }
        public long Size { get; set; }
        public string Hash { get; set; } = "";
    }

    public static class SettingsManager
    {
        // %APPDATA%/AntivirusScanner/config.json
        private static readonly string ConfigDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), 
            "AntivirusScanner"
        );
        private static readonly string ConfigFile = Path.Combine(ConfigDir, "config.json");

        public static AppConfig Load()
        {
            if (!File.Exists(ConfigFile)) return new AppConfig();

            try
            {
                string json = File.ReadAllText(ConfigFile);
                return JsonSerializer.Deserialize<AppConfig>(json) ?? new AppConfig();
            }
            catch
            {
                return new AppConfig();
            }
        }

        public static void Save(AppConfig config)
        {
            try
            {
                if (!Directory.Exists(ConfigDir)) Directory.CreateDirectory(ConfigDir);
                
                string json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(ConfigFile, json);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error guardando configuración: {ex.Message}");
            }
        }
    }
}
