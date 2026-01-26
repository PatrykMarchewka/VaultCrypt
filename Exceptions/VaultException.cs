using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Exceptions
{
    internal class VaultException : Exception
    {
        internal VaultException(string message, Exception innerException) : base($"{message} => {innerException.Message}", innerException) { }
        internal static VaultException EncryptionFailed(Exception inner) => new VaultException("Encryption failed", inner);
        internal static VaultException DecryptionFailed(Exception inner) => new VaultException("Decryption failed", inner);
    }
}
