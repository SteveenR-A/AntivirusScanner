using System;
using System.IO;
using System.Collections.Generic;
using System.Text;
using AntivirusScanner.Utils;

namespace AntivirusScanner.Core
{
    public class LocalScanner
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

        public ScanResult CheckLocalSignatures(string filePath)
        {
            var result = new ScanResult { FilePath = filePath, Status = ScanStatus.Safe };
            
            string magic = GetMagicNumber(filePath);
            string ext = Path.GetExtension(filePath).ToLower();

            foreach (var sig in Signatures)
            {
                if (magic.StartsWith(sig.Key))
                {
                    bool validExt = false;
                    foreach (var valid in sig.Value.Exts) if (ext == valid) validExt = true;

                    if (!validExt)
                    {
                        foreach (var mask in MaskExtensions)
                            if (ext == mask) 
                            { 
                                result.Status = ScanStatus.Suspicious; 
                                result.ThreatType = ThreatType.Spoofing;
                                result.Details = $"Spoofing ({sig.Value.Desc} as {ext})"; 
                                return result;
                            }
                        
                        if (sig.Key == "4d5a") 
                        { 
                            result.Status = ScanStatus.Suspicious;
                            result.ThreatType = ThreatType.Spoofing;
                            result.Details = "Hidden Executable";
                            return result;
                        }
                    }
                    break;
                }
            }
            return result;
        }

        public ScanResult ScanFileContent(string filePath)
        {
            var result = new ScanResult { FilePath = filePath, Status = ScanStatus.Safe };

            try
            {
                FileInfo info = new FileInfo(filePath);
                
                // 1. ANÁLISIS DE ENTROPÍA (Detectar Encriptación/Packers)
                double entropy = CalculateShannonEntropy(filePath);
                
                // Si la entropía es muy alta (> 7.2) y es un ejecutable, es MUY sospechoso (Packed/Encrypted)
                bool isHighEntropy = entropy > 7.2;
                bool isExecutable = IsPEFile(filePath);

                if (isExecutable && isHighEntropy)
                {
                    result.Status = ScanStatus.Suspicious;
                    result.ThreatType = ThreatType.Unknown; // Posible Malware Empaquetado
                    result.Details = $"Heuristic: High Entropy ({entropy:F2}). File might be packed or encrypted.";
                    // Seguimos escaneando por si encontramos firmas conocidas dentro del packer
                }

                // 2. FILTRADO: Si NO es un ejecutable ni script (.ps1, .bat), 
                // NO buscamos firmas de inyección de código para evitar falsos positivos
                if (!isExecutable && !IsScriptFile(filePath))
                {
                    // Solo retornamos si NO marcamos alta entropía antes.
                    // Si marcamos alta entropía, ya es sospechoso, así que devolvemos eso.
                    return result; 
                }

                // 3. ESCANEO DE FIRMAS (Contenido) en Stream
                const int BUFFER_SIZE = 4096; // 4KB chunks
                const int OVERLAP = 128;      // Overlap to catch split patterns
                
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    byte[] buffer = new byte[BUFFER_SIZE];
                    int bytesRead;
                    byte[] carryOver = new byte[0];

                    while ((bytesRead = fs.Read(buffer, 0, BUFFER_SIZE)) > 0)
                    {
                        // Combine carryOver + current buffer to scan across boundaries
                        byte[] searchWindow;
                        if (carryOver.Length > 0)
                        {
                            searchWindow = new byte[carryOver.Length + bytesRead];
                            Buffer.BlockCopy(carryOver, 0, searchWindow, 0, carryOver.Length);
                            Buffer.BlockCopy(buffer, 0, searchWindow, carryOver.Length, bytesRead);
                        }
                        else
                        {
                            searchWindow = new byte[bytesRead];
                            Buffer.BlockCopy(buffer, 0, searchWindow, 0, bytesRead);
                        }

                        // Scan patterns
                        foreach (var pattern in HeuristicPatterns)
                        {
                            if (ContainsBytes(searchWindow, pattern.Value))
                            {
                                // Stronger warning if we found a pattern
                                result.Status = ScanStatus.Suspicious;
                                result.ThreatType = ThreatType.Malware;
                                result.Details = $"Heuristic: Found {pattern.Key}";
                                return result;
                            }
                        }
                        
                        // Check Strong Signatures (Exact Match) - Example EICAR
                        foreach (var pattern in StrongSignatures)
                        {
                             if (ContainsBytes(searchWindow, pattern.Value))
                            {
                                result.Status = ScanStatus.Threat;
                                result.ThreatType = ThreatType.Malware;
                                result.Details = $"CRITICAL: {pattern.Key}";
                                return result;
                            }
                        }

                        // Save last part for overlap
                        if (bytesRead > OVERLAP)
                        {
                            carryOver = new byte[OVERLAP];
                            Buffer.BlockCopy(buffer, bytesRead - OVERLAP, carryOver, 0, OVERLAP);
                        }
                        else
                        {
                            carryOver = new byte[bytesRead];
                            Buffer.BlockCopy(buffer, 0, carryOver, 0, bytesRead);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                result.Status = ScanStatus.Error;
                result.Details = $"Read Error: {ex.Message}";
            }

            return result;
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
                    fs.Read(data, 0, toRead);
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

        private bool IsPEFile(string filePath)
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

        private bool IsScriptFile(string filePath)
        {
            string ext = Path.GetExtension(filePath).ToLower();
            return ext == ".ps1" || ext == ".bat" || ext == ".vbs" || ext == ".cmd" || ext == ".js";
        }

        // Knuth-Morris-Pratt (KMP) or Simple Byte Search
        private bool ContainsBytes(byte[] haystack, byte[] needle)
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

        private string GetMagicNumber(string filePath)
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
