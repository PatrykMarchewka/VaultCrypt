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

        internal ErrorContext ExceptionContext { get; }
        internal ErrorReason ExceptionReason { get; }
        
        internal VaultException(ErrorContext context, ErrorReason reason, Exception? innerException = null) : base($"{GetContext(context)}: {GetReason(reason)}", innerException) {
            ExceptionContext = context;
            ExceptionReason = reason;
        }

        internal enum ErrorContext
        {
            Encrypt,
            Decrypt
        }

        internal static string GetContext(ErrorContext context) => context switch
        {
            ErrorContext.Encrypt => "Encryption failed",
            ErrorContext.Decrypt => "Decryption failed",
            _ => "Unknown error context"
        };

        internal enum ErrorReason
        {
            EndOfFile,
            TaskFaulted,
            WrongHMAC
        }
        internal static string GetReason(ErrorReason reason) => reason switch
        {
            ErrorReason.EndOfFile => "Unexpected end of file",
            ErrorReason.TaskFaulted => "One or more tasks failed",
            ErrorReason.WrongHMAC => "Wrong HMAC authentication tag",
            _ => "Unknown error reason"
        };
    }
}
