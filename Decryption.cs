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
            internal static byte[] DecryptBytes(ReadOnlySpan<byte> data, EncryptionOptions.EncryptionProtocol encryption = EncryptionOptions.EncryptionProtocol.AES256GCM)
            {
                ReadOnlySpan<byte> iv = data.Slice(0,12);
                ReadOnlySpan<byte> tag = data.Slice(12, 16);
                ReadOnlySpan<byte> encryptedData = data.Slice(28);

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
