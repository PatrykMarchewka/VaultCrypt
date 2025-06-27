using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Printing.IndexedProperties;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt
{


    public class CompactVaultEntry
    {
        public ushort nameLength { get; set; } //Fixed 2 bytes
        public string fileName { get; set; } //Varying length, read from nameLength
        public long fileSize { get; set; } //Fixed 8 bytes, size of encrypted file
        public static CompactVaultEntry ReadFrom(Stream stream)
        {
            Span<byte> buffer = stackalloc byte[2];
            stream.ReadExactly(buffer);
            ushort nameLength = BitConverter.ToUInt16(buffer);

            byte[] nameBytes = new byte[nameLength];
            stream.ReadExactly(nameBytes);
            string fileName = Encoding.UTF8.GetString(nameBytes);

            buffer = stackalloc byte[8];
            stream.ReadExactly(buffer);
            long encLength = BitConverter.ToInt64(buffer);

            return new CompactVaultEntry
            {
                nameLength = nameLength,
                fileName = fileName,
                fileSize = encLength
            };
        }


        public static void WriteTo(CompactVaultEntry entry, Stream stream)
        {
            byte[] nameBytes = Encoding.UTF8.GetBytes(entry.fileName);
            if (nameBytes.Length > ushort.MaxValue)
            {
                throw new Exception("File name is too long!");
            }

            Span<byte> buffer = stackalloc byte[2];
            BitConverter.TryWriteBytes(buffer, (ushort)nameBytes.Length);
            stream.Write(buffer);

            stream.Write(nameBytes, 0, nameBytes.Length);

            buffer = stackalloc byte[8];
            BitConverter.TryWriteBytes(buffer, entry.fileSize);
            stream.Write(buffer);

            //Example:
            //WriteTo(meta,fs)
            //fs.write(encryptedbytes,0,encryptedbytes.length
            
        }


    }


    public class VaultEntry
    {
        public long compactVaultEntryOffset { get; set; } //Has to point to beginning of the CompactVaultEntry, not File itself!
        public long fileSize { get; set; } //Size of encrypted file
        public DateTime creationDateUTC { get; set; } = DateTime.UtcNow;
        public NormalizedPath? originalPath { get; set; }
        public VaultContentType contentType { get; set; }
        

        public enum VaultContentType
        {
            Unknown,
            Text,
            Image,
            Audio,
            Video,
            Archive,
            Executable,
            Document
        }

        public static VaultContentType GetContentTypeFromExtension(NormalizedPath filepath)
        {
            string ext = Path.GetExtension(filepath).ToLowerInvariant();
            return ext switch
            {
                ".txt" => VaultContentType.Text,
                ".jpg" or ".jpeg" or ".png" or ".bmp" => VaultContentType.Image,
                ".mp3" or ".wav" => VaultContentType.Audio,
                ".mp4" or ".mov" => VaultContentType.Video,
                ".zip" or ".rar" or ".7z" => VaultContentType.Archive,
                ".exe" or ".msi" => VaultContentType.Executable,
                ".pdf" or ".docx" or ".doc" => VaultContentType.Document,
                _ => VaultContentType.Unknown
            };
        }
    }

    public class IndexMetadata
    {
        public Dictionary<string, VaultEntry> meta { get; set; } = new Dictionary<string, VaultEntry>();
        string formatVersion { get; set; } = "v1.0";
    }
}
