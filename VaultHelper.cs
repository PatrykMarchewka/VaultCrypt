using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace VaultCrypt
{
    internal class VaultHelper
    {
        public static void CreateVault(string vaultPath, string password)
        {
            using (FileStream fs = new FileStream(vaultPath,FileMode.Create))
            {
                byte[] header = Encoding.UTF8.GetBytes("VAULT_FILE");
                fs.Write(header, 0, header.Length);
            }

            File.WriteAllText(vaultPath + "_metadata.enc", "[]");
        }

        public static Dictionary<string, long> ReadMetadataFromVault(string vaultPath, string password)
        {
            using (FileStream fs = new FileStream(vaultPath,FileMode.Open))
            {
                fs.Seek(0, SeekOrigin.Begin);
                byte[] sizeBuffer = new byte[4];
                int metadataSize = BitConverter.ToInt32(sizeBuffer, 0);

                byte[] encryptedMetadata = new byte[metadataSize];
                fs.Read(encryptedMetadata, 0, metadataSize);

                byte[] decryptedMetadata = EncryptionHelper.DecryptBytes(encryptedMetadata, password);
                string json = Encoding.UTF8.GetString(decryptedMetadata);
                return JsonSerializer.Deserialize<Dictionary<string, long>>(json);
            }
        }

        public static void WriteMetadataToVault(string vaultPath, Dictionary<string, long> metadata, string password)
        {
            string json = JsonSerializer.Serialize(metadata);
            byte[] encryptedMetadata = EncryptionHelper.EncryptBytes(Encoding.UTF8.GetBytes(json), password);

            using (FileStream fs = new FileStream(vaultPath,FileMode.Open))
            {
                fs.Seek(0, SeekOrigin.Begin);
                byte[] metadataSize = BitConverter.GetBytes(encryptedMetadata.Length);
                fs.Write(metadataSize, 0, metadataSize.Length);
                fs.Write(encryptedMetadata, 0, encryptedMetadata.Length);
            }
        }

        public static void AppendMetadataToVault(string vaultPath, string fileName, long offset, string password)
        {
            Dictionary<string, long> metadata = ReadMetadataFromVault(vaultPath, password);
            metadata[fileName] = offset;
            throw new NotImplementedException();
        }

        public static void AddFileToVault(string vaultPath, string filePath, string password)
        {
            throw new NotImplementedException();
        }








    }
}
