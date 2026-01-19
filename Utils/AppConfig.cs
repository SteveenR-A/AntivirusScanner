using System.Collections.Generic;

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
        public HashSet<string> BlacklistedHashes { get; set; } = new(); // Offline Blacklist
    }
}
