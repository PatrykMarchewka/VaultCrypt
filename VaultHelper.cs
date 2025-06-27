using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Enumeration;
using System.Linq;
using System.Printing.IndexedProperties;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace VaultCrypt
{
    //File structure
    //Basic Metadata per file then Massive Dictionary with extra stuff, signature to verify it file isn't corrupted and offset to point to the dictionary:
    //[metadata][file][metadata][file][Dictionary][SIG][DictionaryOffset]
    //SIG = 8 bytes
    //DictionaryOffset = 8 bytes


    //TODO
    //Fix when multiple possibly corrupted metadata
    //Possibility of recovery when corrupted metadata at the end but older one exists
    //Add zipping for folders

    internal class VaultHelper
    {


        //TODO: Edit, dont use this
        public static void CreateVault(NormalizedPath vaultPath, string password)
        {
            using (FileStream fs = new FileStream(vaultPath,FileMode.Create))
            {
                byte[] header = Encoding.UTF8.GetBytes("VAULT_FILE");
                fs.Write(header, 0, header.Length);
            }

            File.WriteAllText(vaultPath + "_metadata.enc", "[]");
        }

        /// <summary>
        /// Gets metadata from Vault
        /// </summary>
        /// <param name="vaultPath">Path to the vault</param>
        /// <param name="password">Password to the vault</param>
        /// <returns>IndexMetadata from vault</returns>
        /// <exception cref="Exception"></exception>
        public static IndexMetadata ReadMetadataFromVault(NormalizedPath vaultPath, string password)
        {
            using (FileStream fs = new FileStream(vaultPath,FileMode.Open, FileAccess.Read))
            {
                fs.Seek(-16, SeekOrigin.End);
                byte[] signature = new byte[8];
                fs.Read(signature, 0, 8);
                string sigString = Encoding.ASCII.GetString(signature);

                if (sigString != "VAULTPTR")
                {
                    //TODO: Instead try rebuilding Index from compacts
                    throw new Exception("Vault signature missing or corrupted!");
                }
                long metadataOffset = FindIndexMetadataOffset(vaultPath);

                long metadataSize = fs.Length - 16 - metadataOffset;
                fs.Seek(metadataOffset, SeekOrigin.Begin);
                byte[] encryptedMetadata = new byte[metadataSize];
                fs.Read(encryptedMetadata, 0, encryptedMetadata.Length);

                byte[] decrypted = EncryptionHelper.DecryptBytes(encryptedMetadata, password);
                string json = Encoding.UTF8.GetString(decrypted);
                return JsonSerializer.Deserialize<IndexMetadata>(json);
                //TODO: Change it for potential different version
            }
        }


        /// <summary>
        /// Replaces metadata with new one, if you are just adding files use instead <see cref="AppendMetadataToVault(NormalizedPath, NormalizedPath, long, long, string)"/>
        /// </summary>
        /// <param name="vaultPath">Path for the vault file</param>
        /// <param name="metadata">IndexMetadata instance to save</param>
        /// <param name="password">Password to encrypt with</param>
        public static void WriteMetadataToVault(NormalizedPath vaultPath, IndexMetadata metadata, string password)
        {
            string json = JsonSerializer.Serialize(metadata);
            byte[] encryptedMetadata = EncryptionHelper.EncryptBytes(Encoding.UTF8.GetBytes(json), password);

            using (FileStream fs = new FileStream(vaultPath,FileMode.Open))
            {
                fs.Seek(0, SeekOrigin.End);
                long offset = fs.Position;
                //first write metadata
                fs.Write(encryptedMetadata, 0, encryptedMetadata.Length);
                //second write signature
                byte[] sig = Encoding.ASCII.GetBytes("VAULTPTR");
                fs.Write(sig, 0, sig.Length);
                //third write offset
                byte[] offsetBuffer = BitConverter.GetBytes(offset);
                fs.Write(offsetBuffer, 0, offsetBuffer.Length);

            }
        }

        /// <summary>
        /// Appends metadata to already existing one
        /// </summary>
        /// <param name="vaultPath">Path to the vault</param>
        /// <param name="filePath">Path to the file</param>
        /// <param name="offset">Offset of CompactVaultEntry</param>
        /// <param name="encLength">Length of the encrypted file</param>
        /// <param name="password">Password to the vault</param>
        public static void AppendMetadataToVault(NormalizedPath vaultPath, NormalizedPath filePath, long offset, long encLength, string password)
        {
            FileInfo fileInfo = new FileInfo(filePath);
            IndexMetadata metadata = ReadMetadataFromVault(vaultPath, password);
            metadata.meta.Add(fileInfo.Name, new VaultEntry() { fileSize = encLength, contentType = VaultEntry.GetContentTypeFromExtension(filePath), creationDateUTC = fileInfo.CreationTimeUtc, compactVaultEntryOffset = offset, originalPath = filePath });
            string json = JsonSerializer.Serialize(metadata);
            byte[] encryptedMetadata = EncryptionHelper.EncryptBytes(Encoding.UTF8.GetBytes(json), password);

            using (FileStream fs = new FileStream(vaultPath, FileMode.Open))
            {
                fs.Seek(0, SeekOrigin.End);
                long MetaOffset = fs.Position;
                //first write metadata
                fs.Write(encryptedMetadata, 0, encryptedMetadata.Length);
                //second write signature
                byte[] sig = Encoding.ASCII.GetBytes("VAULTPTR");
                fs.Write(sig, 0, sig.Length);
                //third write offset
                byte[] offsetBuffer = BitConverter.GetBytes(MetaOffset);
                fs.Write(offsetBuffer, 0, offsetBuffer.Length);

            }
        }
        /// <summary>
        /// Finds the position of IndexMetadata in the vault file
        /// </summary>
        /// <param name="vaultPath">Path to the vault</param>
        /// <returns></returns>
        public static long FindIndexMetadataOffset(NormalizedPath vaultPath)
        {
            long offset;
            using (FileStream fs = new FileStream(vaultPath, FileMode.Open))
            {
                fs.Seek(-8, SeekOrigin.End);
                byte[] offsetBuffer = new byte[8];
                fs.Read(offsetBuffer, 0, 8);
                offset = BitConverter.ToInt64(offsetBuffer, 0);
            }
            return offset;
        }

        /// <summary>
        /// Adds file to vault
        /// </summary>
        /// <param name="vaultPath">Path to the vault</param>
        /// <param name="filePath">Path to the file</param>
        /// <param name="password">Password to the vault</param>
        public static void AddFileToVault(NormalizedPath vaultPath, NormalizedPath filePath, string password)
        {
            byte[] encyptedData = EncryptionHelper.EncryptFileToBytes(filePath, password);

            CompactVaultEntry entry = new CompactVaultEntry()
            {
                nameLength = (ushort)Path.GetFileName(filePath).Length,
                fileName = Path.GetFileName(filePath),
                fileSize = encyptedData.LongLength
            };
            long offset;
            using (FileStream fs = new FileStream(vaultPath, FileMode.Append))
            {
                fs.Seek(0, SeekOrigin.End);
                offset = fs.Position;
                CompactVaultEntry.WriteTo(entry, fs);
                fs.Write(encyptedData, 0, encyptedData.Length);
            }

            AppendMetadataToVault(vaultPath, filePath, offset, encyptedData.LongLength, password);
        }

        /// <summary>
        /// Zips the folder and adds as the file to vault
        /// </summary>
        /// <param name="vaultPath">Path to the vault</param>
        /// <param name="folderPath">Path to the folder</param>
        /// <param name="password">Password to the vault</param>
        /// <exception cref="NotImplementedException"></exception>
        public static void AddFolderToVault(NormalizedPath vaultPath, NormalizedPath folderPath, string password)
        {
            //Zip it and send as zip
            throw new NotImplementedException();
        }

        /// <summary>
        /// Safely deletes file from vault, overwriting it with random bytes TODO: fix the parameters, group them
        /// </summary>
        /// <param name="vaultPath">Path to the vault</param>
        /// <param name="fileName">Name of the file to delete</param>
        /// <param name="password">Password to the vault</param>
        /// <param name="overwrites">Optional: Number of overwrites to the file</param>
        /// <exception cref="Exception">Exception thrown when file can't be found in the IndexMetadata</exception>
        public static void DeleteFileFromVault(NormalizedPath vaultPath, string fileName, string password, int overwrites = 3)
        {
            var metadata = ReadMetadataFromVault(vaultPath, password);
            if (!metadata.meta.ContainsKey(fileName))
            {
                //No file???
                throw new Exception("File not found");
            }

            long offset = metadata.meta[fileName].compactVaultEntryOffset;
            CompactVaultEntry com;
            using (FileStream fs = new FileStream(vaultPath, FileMode.Open, FileAccess.ReadWrite))
            {
                fs.Seek(offset, SeekOrigin.Begin);
                com = CompactVaultEntry.ReadFrom(fs);
            }
            long fullsize = 2 + com.nameLength + 8 + metadata.meta[fileName].fileSize; //2 bytes for ushort + name + 8 bytes for filesize number + actual fileSize
            FileHelper.DeleteBytesSecurely(vaultPath, offset, fullsize,overwrites);

            metadata.meta.Remove(fileName);
            WriteMetadataToVault(vaultPath, metadata, password);

        }

        public static void CompactVault(NormalizedPath vaultPath, string password)
        {
            //Call to compactMetadata
            throw new NotImplementedException();
        }








    }
}
