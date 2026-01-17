namespace AntivirusScanner.Core
{
    public enum ScanStatus
    {
        Safe,
        Suspicious,
        Threat,
        Skipped,
        Error
    }

    public enum ThreatType
    {
        None,
        Spoofing,      // Magic Number mismatch / Double Extension
        Malware,       // VirusTotal / Known Hash
        Unknown
    }
}
