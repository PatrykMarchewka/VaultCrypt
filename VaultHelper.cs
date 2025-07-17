using System.Buffers.Binary;
using System.IO;
using System.Text;
using System.Text.Json;

namespace VaultCrypt
{
    public class VaultInfo
    {
        private static NormalizedPath _vaultPath;
        private static string _vaultPassword;

        public static NormalizedPath vaultPath
        {
            get => _vaultPath ?? throw new InvalidOperationException("Vault path cannot not initialized");
            set => _vaultPath = value ?? throw new ArgumentNullException(nameof(value), "Vault path cannot be set to null"); //Nulls not allowed, if there is no vault then it should be empty instead
        }
        public static string vaultPassword
        {
            get => _vaultPassword ?? throw new InvalidOperationException("Password cannot be null");
            set => _vaultPassword = value ?? throw new ArgumentNullException(nameof(value), "Password cannot be set to null");
        }
        public static string? tempLocation { get; set; }
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

                byte[] decrypted = EncryptionHelper.DecryptBytes(encryptedMetadata, VaultInfo.vaultPassword);
                string json = Encoding.UTF8.GetString(decrypted);
                return JsonSerializer.Deserialize<IndexMetadata>(json);
                //TODO: Change it for potential different version
            }
        }


        /// <summary>
        /// Replaces metadata with new one, if you are just adding files use instead <see cref="AppendMetadataToVault(NormalizedPath, NormalizedPath, long, long, string)"/>
        /// </summary>
        /// <param name="metadata">IndexMetadata instance to save</param>
        public static void WriteMetadataToVault(IndexMetadata metadata)
        {
            string json = JsonSerializer.Serialize(metadata);
            byte[] encryptedMetadata = EncryptionHelper.EncryptBytes(Encoding.UTF8.GetBytes(json), VaultInfo.vaultPassword);

            using (FileStream fs = new FileStream(VaultInfo.vaultPath,FileMode.Open))
            using (FileStream fs = new FileStream(VaultInfo.vaultPath,FileMode.Append))
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
        /// <param name="filePath">Path to the file</param>
        /// <param name="offset">Offset of CompactVaultEntry</param>
        /// <param name="encLength">Length of the encrypted file</param>
        public static void AppendMetadataToVault(NormalizedPath filePath, long offset, long encLength)
        {
            FileInfo fileInfo = new FileInfo(filePath);
            IndexMetadata metadata = ReadMetadataFromVault();
            metadata.meta.Add(fileInfo.Name, new VaultEntry() { fileSize = encLength, contentType = VaultEntry.GetContentTypeFromExtension(filePath), creationDateUTC = fileInfo.CreationTimeUtc, compactVaultEntryOffset = offset, originalPath = filePath });
            string json = JsonSerializer.Serialize(metadata);
            byte[] encryptedMetadata = EncryptionHelper.EncryptBytes(Encoding.UTF8.GetBytes(json), VaultInfo.vaultPassword);

            using (FileStream fs = new FileStream(VaultInfo.vaultPath, FileMode.Open))
            using (FileStream fs = new FileStream(VaultInfo.vaultPath, FileMode.Append))
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
        /// Adds file to vault
        /// </summary>
        /// <param name="filePath">Path to the file</param>
        public static void AddFileToVault(NormalizedPath filePath)
        {
            byte[] encyptedData = EncryptionHelper.EncryptFileToBytes(filePath, VaultInfo.vaultPassword);

            CompactVaultEntry entry = new CompactVaultEntry()
            {
                nameLength = (ushort)Path.GetFileName(filePath).Length,
                fileName = Path.GetFileName(filePath),
                fileSize = encyptedData.LongLength
            };
            long offset;
            using (FileStream fs = new FileStream(VaultInfo.vaultPath, FileMode.Append))
            {
                fs.Seek(0, SeekOrigin.End);
                offset = fs.Position;
                CompactVaultEntry.WriteTo(entry, fs);
                fs.Write(encyptedData, 0, encyptedData.Length);
            }

            AppendMetadataToVault(filePath, offset, encyptedData.LongLength);
        }

        /// <summary>
        /// Zips the folder and adds as the file to vault
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
        public static void AddFileToVaultInChunks(NormalizedPath filePath, ushort chunkSizeInMB = 256)
        {

            //fileSize and chunk information set to zero for initialization, it gets populated below with correct information
            CompactVaultEntry entry = new CompactVaultEntry(nameLength: (ushort)Path.GetFileName(filePath).Length, fileName: Path.GetFileName(filePath), fileSize: 0, chunked: true, chunkInformation: new CompactVaultEntry.ChunkInformation(chunkSize: 0, totalChunks: 0, finalChunkSize: 0));




            using FileStream fs = new FileStream(VaultInfo.vaultPath, FileMode.Append);
            using FileStream file = new FileStream(filePath, FileMode.Open, FileAccess.Read);
            long offset = fs.Length;
            uint chunks = FileHelper.GetChunkNumber(filePath);

            CompactVaultEntry.WriteTo(entry, fs);
            
            
            
            //TODO: Finish
            int bytesRead = 0;
            long totalSize = 0; //Total encrypted size
            long lastChunkSize = 0; //Last Chunk Size

            byte[] originalBuffer = new byte[chunkSizeInMB * 1024 * 1024];
            while ((bytesRead = file.Read(originalBuffer,0,originalBuffer.Length)) > 0)
            {
                byte[] chunk = (bytesRead == originalBuffer.Length) ? originalBuffer : originalBuffer[..bytesRead];
                //Encrypt here
                byte[] encrypted = EncryptionHelper.EncryptBytesInChunks(chunk, VaultInfo.vaultPassword, chunkSizeInMB);
                fs.Write(encrypted, 0, encrypted.Length);
                totalSize += encrypted.LongLength;
                lastChunkSize = encrypted.LongLength;
            }

            //Clean File Stream regarding original unencrypted file
            file.Close();
            file.DisposeAsync();


            //Modify the original entry with correct total size and  chunk information | Only for version 0
            //offset to fileSize in CompactVaultEntry = offset (to beginning of CompactVaultEntry) + 1 byte (version) + 2 bytes (ushort for name length) + name length read from ushort)
            long offsetToSize = offset + 1 + 2 + entry.nameLength;
            fs.Seek(offsetToSize, SeekOrigin.Begin);
            Span<byte> buffer = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64LittleEndian(buffer, (ulong)totalSize);
            fs.Write(buffer);
            //Going 1 byte to skip the chunked bool
            fs.Seek(1, SeekOrigin.Current);

            CompactVaultEntry.ChunkInformation updatedChunkInformation = new CompactVaultEntry.ChunkInformation(chunkSize: chunkSizeInMB, totalChunks: chunks, finalChunkSize: (ulong)lastChunkSize);
            CompactVaultEntry.WriteChunkInformation(chunk: updatedChunkInformation, stream: fs);


            AppendMetadataToVault(filePath, offset, totalSize);
        }
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
        public static void RebuildVault()
        {
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
