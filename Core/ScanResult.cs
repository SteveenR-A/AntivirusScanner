namespace AntivirusScanner.Core
{
    public class ScanResult
    {
        public string FilePath { get; set; } = "";
        public ScanStatus Status { get; set; } = ScanStatus.Error;
        public ThreatType ThreatType { get; set; } = ThreatType.None;
        public string Details { get; set; } = "";
        
        public bool IsSafe => Status == ScanStatus.Safe || Status == ScanStatus.Skipped;
    }
}
