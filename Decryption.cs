using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt
{
    internal class Decryption
    {

        internal static class AesGcmDecryption
        {
            internal static byte[] DecryptBytes(byte[] data, Encryption.EncryptionProtocol encryption)
            {
                Span<byte> iv = data.AsSpan(0, 12);
                Span<byte> tag = data.AsSpan(12, 16);
                Span<byte> encryptedData = data.AsSpan(28);

                byte[] decrypted = new byte[encryptedData.Length];
                using (AesGcm aesGcm = new AesGcm(VaultSession.KEY, AesGcm.TagByteSizes.MaxSize))
                {
                    aesGcm.Decrypt(iv, encryptedData, tag, decrypted);
                }

                return decrypted;
            }




        }
    }
}
