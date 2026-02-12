using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt
{
    public class EncryptedFileInfo
    {
        public string FileName { get; init; }
        public string FileSize { get; init; }
        public string EncryptionAlgorithm { get; init; }

        internal EncryptedFileInfo(string fileName, ulong fileSize, EncryptionAlgorithm.EncryptionAlgorithmEnum? algorithmEnum = null)
        {
            this.FileName = fileName;
            this.FileSize = FormatSize(fileSize);
            this.EncryptionAlgorithm = algorithmEnum?.ToString() ?? "Unknown";
        }

        private static string FormatSize(ulong fileSize)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB", "PB" };
            double copy = fileSize;
            byte order = 0;
            while (copy >= 1024 && order < sizes.Length - 1)
            {
                order++;
                copy /= 1024;
            }

            return $"{copy:0.##}{sizes[order]}";
        }
    }
}
