using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt
{
    internal class VaultSession : IDisposable
    {
        internal static byte[] KEY;
        internal static NormalizedPath VAULTPATH;
        internal static int ITERATIONS;
        internal static byte[] SALT;
        internal static Dictionary<String, Encryption.FileEncryptionOptions> ENCRYPTED_FILES;

        public void Dispose()
        {
            Array.Clear(KEY, 0, KEY.Length);
            Array.Clear(SALT, 0, SALT.Length);
            ENCRYPTED_FILES.Clear();
            VAULTPATH = NormalizedPath.From(String.Empty);
            ITERATIONS = 0;
        }
    }

