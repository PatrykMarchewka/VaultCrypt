using System.Buffers.Binary;
using System.IO;
using System.Printing.IndexedProperties;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace VaultCrypt
{
    internal class VaultInfo : IDisposable
    {
        private static NormalizedPath _vaultPath;
        private static byte[] _vaultKey;

        public static NormalizedPath vaultPath
        {
            get => _vaultPath ?? throw new InvalidOperationException("Vault path cannot not initialized");
            set => _vaultPath = value ?? throw new ArgumentNullException(nameof(value), "Vault path cannot be set to null"); //Nulls not allowed, if there is no vault then it should be empty instead
        }
        public static byte[] vaultKey
        {
            get => _vaultKey ?? throw new InvalidOperationException("Key cannot be null");
            set => _vaultKey = value ?? throw new ArgumentNullException(nameof(value), "Key cannot be set to null");
        }
        public static string? tempLocation { get; set; }
        public void Dispose()
        {
            if (_vaultKey != null)
            {
                Array.Clear(_vaultKey);
            }
            _vaultPath = NormalizedPath.From(String.Empty);
        }
    }


    internal class VaultHelper
    {


        //TODO: Edit, dont use this
        //Make it require atleast one file
        public static void CreateVault()
        {
            using (FileStream fs = new FileStream(VaultInfo.vaultPath,FileMode.Create))
            {
                byte[] header = Encoding.UTF8.GetBytes("VAULT_FILE");
                fs.Write(header, 0, header.Length);
            }

            File.WriteAllText(VaultInfo.vaultPath + "_metadata.enc", "[]");
        }

        //TODO: Finish
        /// <summary>
        /// Basic operations after opening the vault
        /// </summary>
        /// <param name="path"></param>
        /// <param name="password"></param>
        public static void OpenVault(NormalizedPath path, string password)
        {
            VaultInfo.vaultPath = path;
            using (FileStream fs = new FileStream(path,FileMode.Open,FileAccess.Read))
            {
                Span<byte> buffer = stackalloc byte[1];
                fs.ReadExactly(buffer);
                byte version = buffer[0];
                EncryptionHelper.EncryptionOptions options = ReaderFactory.getReader(version).ReadEncryptionOptions(fs);
                VaultInfo.vaultKey = EncryptionHelper.DeriveKey(password, options);
            }
        }

        /// <summary>
        /// Gets metadata from Vault
        /// </summary>
        /// <returns>IndexMetadata from vault</returns>
        /// <exception cref="Exception"></exception>
        /// 
        public static IndexMetadata ReadMetadataFromVault()
        {
            using (FileStream fs = new FileStream(VaultInfo.vaultPath, FileMode.Open, FileAccess.Read))
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
                long metadataOffset = FindIndexMetadataOffset();

                long metadataSize = fs.Length - 16 - metadataOffset;
                fs.Seek(metadataOffset, SeekOrigin.Begin);
                byte[] encryptedMetadata = new byte[metadataSize];
                fs.Read(encryptedMetadata, 0, encryptedMetadata.Length);

                byte[] decrypted = EncryptionHelper.DecryptBytes(encryptedMetadata, key: null);
                string json = Encoding.UTF8.GetString(decrypted);
                return JsonSerializer.Deserialize<IndexMetadata>(json);
                //TODO: Change it in future for potential different version
            }
        }


        /// <summary>
        /// Replaces metadata with new one, if you are just adding files use instead <see cref="AppendMetadataToVault(NormalizedPath, long, long)"/>
        /// </summary>
        /// <param name="metadata">IndexMetadata instance to save</param>
        public static void WriteMetadataToVault(IndexMetadata metadata)
        {
            string json = JsonSerializer.Serialize(metadata);
            byte[] encryptedMetadata = EncryptionHelper.EncryptBytes(Encoding.UTF8.GetBytes(json), key: null);
            
            using (FileStream fs = new FileStream(VaultInfo.vaultPath,FileMode.Append))
            {
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
        /// <param name="filePath">Path to the file</param>
        /// <param name="offset">Offset of CompactVaultEntry</param>
        /// <param name="encLength">Length of the encrypted file</param>
        public static void AppendMetadataToVault(NormalizedPath filePath, long offset, long encLength)
        {
            FileInfo fileInfo = new FileInfo(filePath);
            IndexMetadata metadata = ReadMetadataFromVault();
            metadata.meta.Add(fileInfo.Name, new VaultEntry() { fileSize = encLength, contentType = VaultEntry.GetContentTypeFromExtension(filePath), creationDateUTC = fileInfo.CreationTimeUtc, compactVaultEntryOffset = offset, originalPath = filePath });
            string json = JsonSerializer.Serialize(metadata);
            byte[] encryptedMetadata = EncryptionHelper.EncryptBytes(Encoding.UTF8.GetBytes(json), key: null);

            using (FileStream fs = new FileStream(VaultInfo.vaultPath, FileMode.Append))
            {
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
        /// <returns>offset of the IndexMetadata</returns>
        public static long FindIndexMetadataOffset()
        {
            long offset;
            using (FileStream fs = new FileStream(VaultInfo.vaultPath, FileMode.Open))
            {
                fs.Seek(-8, SeekOrigin.End);
                byte[] offsetBuffer = new byte[8];
                fs.Read(offsetBuffer, 0, 8);
                offset = BitConverter.ToInt64(offsetBuffer, 0);
            }
            return offset;
        }

        /// <summary>
        /// Adds file to vault, performing encryption after loading entire file into RAM
        /// </summary>
        /// <param name="filePath">Path to the file</param>
        public static void AddFileToVault(NormalizedPath filePath)
        {
            byte[] key = password == null ? VaultInfo.vaultKey : EncryptionHelper.DeriveKey(password, options);
            byte[] encryptedData = EncryptionHelper.EncryptFileToBytes(filePath, key);

            CompactVaultEntry entry = new CompactVaultEntry(nameLength: (ushort)Path.GetFileName(filePath).Length, fileName: Path.GetFileName(filePath), fileSize: (ulong)encryptedData.LongLength, chunked: false, chunkInformation: null, encryptionOptions: options);

            long offset;
            using (FileStream fs = new FileStream(VaultInfo.vaultPath, FileMode.Append))
            {
                offset = fs.Position;
                CompactVaultEntry.WriteTo(entry, fs);
                fs.Write(encryptedData, 0, encryptedData.Length);
            }

            AppendMetadataToVault(filePath, offset, encryptedData.LongLength);
        }

        /// <summary>
        /// Zips the folder and adds as the file to vault, performing encryption after loading entire file into RAM
        /// </summary>
        /// <param name="folderPath">Path to the folder</param>
        /// <exception cref="NotImplementedException"></exception>
        public static void AddFolderToVault(NormalizedPath folderPath)
        {
            //Zip it and send as zip
            throw new NotImplementedException();
        }


        /// <summary>
        /// Adds file to vault, file is split into chunks to not overload system memory
        /// </summary>
        /// <param name="filePath">Path to the file</param>
        /// <param name="chunkSizeInMB">Size of one chunk in MegaBytes, defaults to 256MB</param>
        public static void AddFileToVaultInChunks(NormalizedPath filePath, string? password, EncryptionHelper.EncryptionOptions options, ushort chunkSizeInMB = 256)
        {
            using FileStream fs = new FileStream(VaultInfo.vaultPath, FileMode.Append);
            using FileStream file = new FileStream(filePath, FileMode.Open, FileAccess.Read);
            long offset = fs.Length;
            uint chunks = FileHelper.GetChunkNumber(filePath);

            byte[] key = password == null ? VaultInfo.vaultKey : EncryptionHelper.DeriveKey(password, options);

            
            int bytesRead = 0;
            long totalSize = 0; //Total encrypted size
            long lastChunkSize = 0; //Last Chunk Size

            byte[] originalBuffer = new byte[chunkSizeInMB * 1024 * 1024];
            while ((bytesRead = file.Read(originalBuffer,0,originalBuffer.Length)) > 0)
            {
                byte[] chunk = (bytesRead == originalBuffer.Length) ? originalBuffer : originalBuffer[..bytesRead];
                //Encrypt here
                byte[] encrypted = EncryptionHelper.EncryptBytes(chunk, key);
                fs.Write(encrypted, 0, encrypted.Length);
                totalSize += encrypted.LongLength;
                lastChunkSize = encrypted.LongLength;
            }

            //Clean File Stream regarding original unencrypted file
            file.Close();
            file.DisposeAsync();

            //Writing metadata entry
            CompactVaultEntry entry = new CompactVaultEntry(nameLength: (ushort)Path.GetFileName(filePath).Length, fileName: Path.GetFileName(filePath), fileSize: 0, chunked: true, chunkInformation: new CompactVaultEntry.ChunkInformation(chunkSize: chunkSizeInMB, totalChunks: chunks, finalChunkSize: (ulong)lastChunkSize), encryptionOptions: options);
            CompactVaultEntry.WriteTo(entry, fs);


            AppendMetadataToVault(filePath, offset, totalSize);
        }

        public static void AddFolderToVaultInChunks(NormalizedPath folderPath)
        {
            throw new NotImplementedException();
        }



        //TODO: Check long fullsize, might be not working due to difference in CompactVaultEntry size
        /// <summary>
        /// Safely deletes file from vault, overwriting it with random bytes
        /// </summary>
        /// <param name="fileName">Name of the file to delete</param>
        /// <param name="overwrites">Optional: Number of overwrites to the file</param>
        /// <exception cref="Exception">Exception thrown when file can't be found in the IndexMetadata</exception>
        public static void DeleteFileFromVault(string fileName, int overwrites = 3)
        {
            var metadata = ReadMetadataFromVault();
            if (!metadata.meta.ContainsKey(fileName))
            {
                //No file???
                throw new Exception("File not found");
            }

            long offset = metadata.meta[fileName].compactVaultEntryOffset;
            CompactVaultEntry com;
            using (FileStream fs = new FileStream(VaultInfo.vaultPath, FileMode.Open, FileAccess.ReadWrite))
            {
                fs.Seek(offset, SeekOrigin.Begin);
                com = CompactVaultEntry.ReadFrom(fs);
            }
            long fullsize = 2 + com.nameLength + 8 + metadata.meta[fileName].fileSize; //2 bytes for ushort + name + 8 bytes for filesize number + actual fileSize
            FileHelper.DeleteBytesSecurely(offset, fullsize,overwrites);

            metadata.meta.Remove(fileName);
            WriteMetadataToVault(metadata);

        }

        /// <summary>
        /// Recreates the vault from scratch and deletes old one. Used to shrink vault size if current vault has leftover data
        /// </summary>
        public static void RebuildVault(EncryptionHelper.EncryptionOptions? newOptions)
        {
            if (!FileHelper.CheckFreeSpace(VaultInfo.vaultPath))
            {
                //Not enough free space
                throw new Exception("Not enough free space on disk");
            }
            NormalizedPath newPath = NormalizedPath.From(VaultInfo.vaultPath + ".tmp");
            IndexMetadata metadata = ReadMetadataFromVault();

            using var sourceStream = new FileStream(VaultInfo.vaultPath, FileMode.Open, FileAccess.ReadWrite);
            using var newVault = new FileStream(newPath, FileMode.CreateNew, FileAccess.Write);
            foreach (var (name, entry) in metadata.meta)
            {
                sourceStream.Seek(entry.compactVaultEntryOffset, SeekOrigin.Begin);
                CompactVaultEntry compactEntry = CompactVaultEntry.ReadFrom(sourceStream);

                long newOffset = newVault.Position;
                CompactVaultEntry.WriteTo(compactEntry, newVault);
                byte[] fileBytes = new byte[entry.fileSize];
                sourceStream.ReadExactly(fileBytes);
                newVault.Write(fileBytes);

                entry.compactVaultEntryOffset = newOffset;
            }
            WriteMetadataToVault(metadata);
            File.Replace(newPath, VaultInfo.vaultPath, VaultInfo.vaultPath + ".err");
        }








    }
}
