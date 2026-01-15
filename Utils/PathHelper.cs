using System;
using System.Runtime.InteropServices;
using System.IO;

namespace AntivirusScanner.Utils
{
    public static class PathHelper
    {
        private static readonly Guid DownloadsFolderGuid = new Guid("374DE290-123F-4565-9164-39C4925E467B");

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, PreserveSig = false)]
        private static extern string SHGetKnownFolderPath([MarshalAs(UnmanagedType.LPStruct)] Guid rfid, uint dwFlags, IntPtr hToken = default);

        /// <summary>
        /// Obtiene la ruta real de la carpeta Descargas de Windows de forma robusta.
        /// </summary>
        public static string GetDownloadsFolder()
        {
            try
            {
                // Intenta obtener la ruta nativa usando la API de Windows
                return SHGetKnownFolderPath(DownloadsFolderGuid, 0);
            }
            catch
            {
                // Fallback en caso de error extremo (ej. ejecutando en un entorno no estándar o Wine mal configurado)
                return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
            }
        }
    }
}
