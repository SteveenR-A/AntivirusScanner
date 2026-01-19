using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using System.Diagnostics;

namespace AntivirusScanner.Core
{
    public class VirusTotalService
    {
        private readonly HttpClient _client;
        private DateTime _nextAllowedRequest = DateTime.MinValue;
        
        // 4 requests per minute = 1 request every 15 seconds
        private readonly TimeSpan _rateLimitInterval = TimeSpan.FromSeconds(15); 

        public VirusTotalService()
        {
            _client = new HttpClient();
        }

        public async Task<int> CheckFileHashAsync(string hash, AntivirusScanner.Utils.AppConfig config)
        {
            if (string.IsNullOrEmpty(config.ApiKey)) return 0;

            // 1. Daily Reset Logic
            if (config.LastApiDate.Date < DateTime.UtcNow.Date)
            {
                config.DailyApiUsage = 0;
                config.LastApiDate = DateTime.UtcNow.Date;
            }

            // 2. Daily Quota Check (500 limit)
            if (config.DailyApiUsage >= 500)
            {
                return -2; // Code for 'Quota Exceeded'
            }

            // Handle Rate Limiting (Token Bucket / Time check)
            var now = DateTime.Now;
            if (now < _nextAllowedRequest)
            {
                var waitTime = _nextAllowedRequest - now;
                Debug.WriteLine($"[VirusTotal] Rate limit active. Waiting {waitTime.TotalSeconds:F1}s...");
                await Task.Delay(waitTime);
            }

            // Set next allowed time immediately
            _nextAllowedRequest = DateTime.Now.Add(_rateLimitInterval);

            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/files/{hash}");
                request.Headers.Add("x-apikey", config.ApiKey);

                using var response = await _client.SendAsync(request);

                // Increment usage regardless of success to be safe/conservative
                config.DailyApiUsage++;
                config.LastApiDate = DateTime.UtcNow.Date;

                if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    return 0; // File unknown (clean by default)
                }

                if (response.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
                {
                    // Penalization: wait longer if we hit the limit
                    _nextAllowedRequest = DateTime.Now.AddSeconds(60); 
                    Debug.WriteLine("[VirusTotal] Quota exceeded (429). Backing off for 60s.");
                    return -1;
                }

                if (!response.IsSuccessStatusCode)
                {
                    Debug.WriteLine($"[VirusTotal] API Error: {response.StatusCode}");
                    return -1;
                }

                string json = await response.Content.ReadAsStringAsync();
                
                using var doc = JsonDocument.Parse(json);
                var stats = doc.RootElement
                               .GetProperty("data")
                               .GetProperty("attributes")
                               .GetProperty("last_analysis_stats");
                
                int malicious = stats.GetProperty("malicious").GetInt32();
                return malicious;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[VirusTotal] Exception: {ex.Message}");
                return -1;
            }
        }
    }
}
