using System;
using System.IO;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using AntivirusScanner.Utils;

namespace AntivirusScanner.Core
{
    public static class LocalScanner
    {
        // Reglas más específicas para evitar falsos positivos
        private static readonly Dictionary<string, byte[]> StrongSignatures = new()
        {
            // EICAR Test File (Firma estándar mundial para pruebas de AV)
            { "EICAR Test Signature", Encoding.ASCII.GetBytes("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*") }
        };

        // Strings sospechosos para heurística (Solo alertar si hay entropía alta o es un EXE)
        private static readonly Dictionary<string, byte[]> HeuristicPatterns = new()
        {
            { "PowerShell Hidden", new byte[] { 0x70, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x65, 0x00, 0x72, 0x00, 0x73, 0x00, 0x68, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x20, 0x00, 0x2D, 0x00, 0x48, 0x00 } }, // "powershell -H" (Unicode)
            { "Process Injection", Encoding.ASCII.GetBytes("CreateRemoteThread") },
            { "Memory Manip", Encoding.ASCII.GetBytes("VirtualAlloc") }
        };

        // File Signatures (Magic Numbers)
        private static readonly Dictionary<string, (string Desc, string[] Exts)> Signatures = new()
        {
            { "7f454c46", ("ELF (Linux)", new[] { ".elf", ".bin", ".o", ".so" }) },
            { "4d5a",     ("EXE (Windows)", new[] { ".exe", ".dll", ".msi", ".com", ".sys" }) },
            { "25504446", ("PDF", new[] { ".pdf" }) },
            { "504b0304", ("ZIP/Office", new[] { ".zip", ".jar", ".apk", ".docx", ".xlsx" }) }
        };

        private static readonly string[] MaskExtensions = { ".jpg", ".png", ".txt", ".mp4", ".doc", ".pdf" };

        public static ScanResult CheckLocalSignatures(string filePath)
        {
            var result = new ScanResult { FilePath = filePath, Status = ScanStatus.Safe };

            string magic = GetMagicNumber(filePath);
            string ext = Path.GetExtension(filePath).ToLower();

            var match = Signatures.FirstOrDefault(s => magic.StartsWith(s.Key));
            if (match.Key != null)
            {
                return ValidateSignature(match, ext, filePath);
            }
            return result;
        }

        private static ScanResult ValidateSignature(KeyValuePair<string, (string Desc, string[] Exts)> sig, string ext, string filePath)
        {
            if (IsExtensionValid(ext, sig.Value.Exts))
            {
                return new ScanResult { FilePath = filePath, Status = ScanStatus.Safe };
            }

            if (IsMaskExtension(ext))
            {
                return new ScanResult
                {
                    FilePath = filePath,
                    Status = ScanStatus.Suspicious,
                    ThreatType = ThreatType.Spoofing,
                    Details = $"Spoofing ({sig.Value.Desc} as {ext})"
                };
            }

            if (sig.Key == "4d5a")
            {
                return new ScanResult
                {
                    FilePath = filePath,
                    Status = ScanStatus.Suspicious,
                    ThreatType = ThreatType.Spoofing,
                    Details = "Hidden Executable"
                };
            }

            return new ScanResult { FilePath = filePath, Status = ScanStatus.Safe };
        }

        private static bool IsExtensionValid(string ext, string[] validExtensions) => validExtensions.Contains(ext);

        private static bool IsMaskExtension(string ext) => MaskExtensions.Contains(ext);

        public static ScanResult ScanFileContent(string filePath)
        {
            try
            {
                var result = AnalyzeEntropy(filePath);

                if (!ShouldScanContent(filePath))
                {
                    return result;
                }

                var patternResult = ScanStreamForPatterns(filePath);
                if (patternResult.Status != ScanStatus.Safe)
                {
                    return patternResult;
                }

                return result;
            }
            catch (Exception ex)
            {
                return new ScanResult { FilePath = filePath, Status = ScanStatus.Error, Details = $"Read Error: {ex.Message}" };
            }
        }

        private static ScanResult AnalyzeEntropy(string filePath)
        {
            var result = new ScanResult { FilePath = filePath, Status = ScanStatus.Safe };
            double entropy = CalculateShannonEntropy(filePath);

            if (entropy > 7.2 && IsPEFile(filePath))
            {
                FileInfo info = new FileInfo(filePath);
                if (info.Length < 10 * 1024 * 1024)
                {
                    result.Status = ScanStatus.Suspicious;
                    result.ThreatType = ThreatType.Unknown;
                    result.Details = $"Heuristic: High Entropy ({entropy:F2}). File might be packed or encrypted.";
                }
            }
            return result;
        }

        private static bool ShouldScanContent(string filePath)
        {
            return IsPEFile(filePath) || IsScriptFile(filePath);
        }

        private static ScanResult ScanStreamForPatterns(string filePath)
        {
            const long LARGE_FILE_THRESHOLD = 50 * 1024 * 1024; // 50MB
            const long SCAN_CHUNK_SIZE = 5 * 1024 * 1024; // 5MB

            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (fs.Length > LARGE_FILE_THRESHOLD)
                {
                    // Scan Head
                    fs.Position = 0;
                    var match = ScanStreamSegment(fs, SCAN_CHUNK_SIZE);
                    if (match != null)
                    {
                        match.FilePath = filePath;
                        return match;
                    }

                    // Scan Tail
                    fs.Position = Math.Max(0, fs.Length - SCAN_CHUNK_SIZE);
                    match = ScanStreamSegment(fs, SCAN_CHUNK_SIZE);
                    if (match != null)
                    {
                        match.FilePath = filePath;
                        return match;
                    }
                }
                else
                {
                    var match = ScanStreamSegment(fs, fs.Length);
                    if (match != null)
                    {
                        match.FilePath = filePath;
                        return match;
                    }
                }
            }

            return new ScanResult { FilePath = filePath, Status = ScanStatus.Safe };
        }

        private static ScanResult? ScanStreamSegment(Stream fs, long maxBytesToRead)
        {
            const int BUFFER_SIZE = 4096;
            const int OVERLAP = 128;

            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            byte[] carryOver = new byte[0];
            long totalRead = 0;

            while (totalRead < maxBytesToRead && (bytesRead = fs.Read(buffer, 0, BUFFER_SIZE)) > 0)
            {
                totalRead += bytesRead;
                byte[] searchWindow = CreateSearchWindow(buffer, bytesRead, carryOver);

                var match = CheckPatterns(searchWindow);
                if (match != null) return match;

                carryOver = UpdateCarryOver(buffer, bytesRead, OVERLAP);
            }
            return null;
        }

        private static byte[] CreateSearchWindow(byte[] buffer, int bytesRead, byte[] carryOver)
        {
            if (carryOver.Length > 0)
            {
                byte[] searchWindow = new byte[carryOver.Length + bytesRead];
                Buffer.BlockCopy(carryOver, 0, searchWindow, 0, carryOver.Length);
                Buffer.BlockCopy(buffer, 0, searchWindow, carryOver.Length, bytesRead);
                return searchWindow;
            }
            else
            {
                byte[] searchWindow = new byte[bytesRead];
                Buffer.BlockCopy(buffer, 0, searchWindow, 0, bytesRead);
                return searchWindow;
            }
        }

        private static ScanResult? CheckPatterns(byte[] searchWindow)
        {
            var heuristicMatch = HeuristicPatterns
                .Where(pattern => ContainsBytes(searchWindow, pattern.Value))
                .Select(pattern => new ScanResult
                {
                    Status = ScanStatus.Suspicious,
                    ThreatType = ThreatType.Malware,
                    Details = $"Heuristic: Found {pattern.Key}"
                })
                .FirstOrDefault();

            if (heuristicMatch != null) return heuristicMatch;

            return StrongSignatures
                .Where(pattern => ContainsBytes(searchWindow, pattern.Value))
                .Select(pattern => new ScanResult
                {
                    Status = ScanStatus.Threat,
                    ThreatType = ThreatType.Malware,
                    Details = $"CRITICAL: {pattern.Key}"
                })
                .FirstOrDefault();
        }

        private static byte[] UpdateCarryOver(byte[] buffer, int bytesRead, int overlap)
        {
            if (bytesRead > overlap)
            {
                byte[] carryOver = new byte[overlap];
                Buffer.BlockCopy(buffer, bytesRead - overlap, carryOver, 0, overlap);
                return carryOver;
            }
            else
            {
                byte[] carryOver = new byte[bytesRead];
                Buffer.BlockCopy(buffer, 0, carryOver, 0, bytesRead);
                return carryOver;
            }
        }

        /// <summary>
        /// Calcula la Entropía de Shannon.
        /// Valor de 0.0 a 8.0.
        /// > 7.0 indica datos altamente aleatorios (Encriptación o Compresión).
        /// </summary>
        public static double CalculateShannonEntropy(string file)
        {
            try
            {
                // Para rendimiento en archivos gigantes, leemos solo una muestra significativa (ej. los primeros 512KB)
                // Muchos packers modifican el EntryPoint que suele estar al principio.
                const int SAMPLE_SIZE = 512 * 1024; 
                byte[] data;
                
                using (var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    int toRead = (int)Math.Min(fs.Length, SAMPLE_SIZE);
                    data = new byte[toRead];
                    int bytesRead = fs.Read(data, 0, toRead);
                    
                    if (bytesRead < toRead)
                    {
                        Array.Resize(ref data, bytesRead);
                    }
                }

                if (data.Length == 0) return 0;

                var frequencies = new int[256];
                foreach (byte b in data)
                {
                    frequencies[b]++;
                }

                double entropy = 0;
                double totalBytes = data.Length;

                foreach (int count in frequencies)
                {
                    if (count == 0) continue;
                    double p = count / totalBytes;
                    entropy -= p * Math.Log(p, 2);
                }

                return entropy;
            }
            catch { return 0; }
        }

        private static bool IsPEFile(string filePath)
        {
            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read);
                if (fs.Length < 2) return false;
                
                int b1 = fs.ReadByte();
                int b2 = fs.ReadByte();

                // 'M' = 77 (0x4D), 'Z' = 90 (0x5A)
                return (b1 == 0x4D && b2 == 0x5A);
            }
            catch { return false; }
        }

        private static bool IsScriptFile(string filePath)
        {
            string ext = Path.GetExtension(filePath).ToLower();
            return ext == ".ps1" || ext == ".bat" || ext == ".vbs" || ext == ".cmd" || ext == ".js";
        }

        // Knuth-Morris-Pratt (KMP) or Simple Byte Search
        private static bool ContainsBytes(byte[] haystack, byte[] needle)
        {
            int len = needle.Length;
            int limit = haystack.Length - len;
            for (int i = 0; i <= limit; i++)
            {
                int k = 0;
                for (; k < len; k++)
                {
                    if (needle[k] != haystack[i + k]) break;
                }
                if (k == len) return true;
            }
            return false;
        }

        private static string GetMagicNumber(string filePath)
        {
            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read);
                using var br = new BinaryReader(fs);
                if (br.BaseStream.Length < 4) return "";
                byte[] bytes = br.ReadBytes(4);
                return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
            }
            catch { return ""; }
        }
    }
}
