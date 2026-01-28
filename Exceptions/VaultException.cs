using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Exceptions
{
    internal class VaultException : Exception
    {
        internal VaultException(string message, Exception? innerException = null) : base(message, innerException) { }


        internal static VaultException EncryptionFailed(Exception inner) => new VaultException("Encryption failed", inner);
        internal static VaultException DecryptionFailed(Exception inner) => new VaultException("Decryption failed", inner);
        internal static VaultException EndOfFileException(Exception? inner = null) => new VaultException("Unexpected end of file!", inner);
        internal static VaultException OperationCancelledException(OperationCanceledException inner) => new VaultException("Operation cancelled by user", inner);
    }
}
