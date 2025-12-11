using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt
{
    internal class FileHelper
    {
        internal static void CreateVault(NormalizedPath folderPath, string vaultName, byte saltSize, uint iterations)
        {
            Span<byte> buffer = stackalloc byte[1 + saltSize + 4]; //1 byte for saltSize + salt + 4 bytes for iterations number
            buffer[0] = saltSize;
            byte[] salt = PasswordHelper.GenerateRandomSalt(saltSize);
            salt.AsSpan().CopyTo(buffer.Slice(1, saltSize));
            BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(1 + saltSize, 4), iterations);

            using (var fs = File.Create(folderPath + vaultName + ".vlt"))
            {
                fs.Write(buffer);
                long position = fs.Position;
                Span<byte> offset = stackalloc byte[16];
                Encoding.UTF8.GetBytes("VAULTPTR").AsSpan().CopyTo(offset);
                BinaryPrimitives.WriteInt64LittleEndian(offset.Slice(8), position);
                fs.Write(offset);
            }
        }

        internal static long GetMetadataOffset(Stream stream)
        {
            stream.Seek(-16, SeekOrigin.End);
            Span<byte> buffer = stackalloc byte[16];
            stream.ReadExactly(buffer);
            string SIG = Encoding.UTF8.GetString(buffer[..8].ToArray());
            if (SIG != "VAULTPTR")
            {
                throw new Exception("Vault signature missing or corrupted!");
            }


            return BinaryPrimitives.ReadInt64LittleEndian(buffer.Slice(8,8));
        }
        internal static bool WriteSmallFile()
        {
            try
            {
                string path = VaultSession.VAULTPATH + "vault.tmp";
                byte[] data = new byte[1024];
                RandomNumberGenerator.Fill(data);

                File.WriteAllBytes(path, data);

                byte[] returned = File.ReadAllBytes(path);

                if (data.Length != returned.Length)
                {
                    return false;
                }

                for (int i = 0; i < data.Length; i++)
                {
                    if (data[i] != returned[i])
                    {
                        return false;
                    }
                }

                return true;
            }
            catch
            {
                throw new Exception("Cant save file to disk");
            }
            finally
            {
                DeleteSmallFile();
            }
        }

        private static void DeleteSmallFile()
        {
            string path = VaultSession.VAULTPATH + "vault.tmp";
            try
            {
                File.Delete(path);
            }
            catch
            {
                throw new Exception("Cannot delete vault.tmp");
            }
        }
    }
    internal class NormalizedPath
    {
        internal string Value { get; }
        private NormalizedPath(string path)
        {
            Value = Normalize(path);
        }
        internal static string Normalize(string path)
        {
            return path.Length > 260 && !path.StartsWith(@"\\?\") ? @"\\?\" + path : path;
        }

        internal static NormalizedPath From(string input) => new NormalizedPath(input);

        public override string ToString()
        {
            return Value;
        }

        public static implicit operator string(NormalizedPath path) => path.Value;


    }

}
