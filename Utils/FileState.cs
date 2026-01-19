using System;

namespace AntivirusScanner.Utils
{
    public class FileState
    {
        public DateTime LastModified { get; set; }
        public long Size { get; set; }
        public string Hash { get; set; } = "";
        public string Status { get; set; } = ""; // SAFE, THREAT, UNKNOWN
    }
}
