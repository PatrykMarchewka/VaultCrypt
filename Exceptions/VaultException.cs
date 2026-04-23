using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Exceptions
{
    public class VaultException : Exception
    {
        public ErrorContext ExceptionContext { get; }
        public ErrorReason ExceptionReason { get; }

        public VaultException(ErrorContext context, ErrorReason reason, Exception? innerException = null) : base($"{GetContext(context)}: {GetReason(reason)}", innerException) {
            ExceptionContext = context;
            ExceptionReason = reason;
        }

        public enum ErrorContext
        {
            Encrypt,
            Decrypt,
            EncryptionOptions,
            SystemCheck,
            VaultSession,
            WriteToFile
        }

        public static string GetContext(ErrorContext context) => context switch
        {
            ErrorContext.Encrypt => "Encryption failed",
            ErrorContext.Decrypt => "Decryption failed",
            ErrorContext.EncryptionOptions => "Encryption options operation failed",
            ErrorContext.SystemCheck => "System check failed",
            ErrorContext.VaultSession => "Vault operation failed",
            ErrorContext.WriteToFile => "Writing to file failed",
            _ => "Unknown error context"
        };

        public enum ErrorReason
        {
            EndOfFile,
            FileNameTooLong,
            FullVault,
            MissingChunk,
            NoFreeSpace,
            NoReader,
            Other,
            TaskFaulted,
            WrongHMAC,
            EmptyFile,
            OperationCancelled,
            MaxRetriesReached
        }
        public static string GetReason(ErrorReason reason) => reason switch
        {
            ErrorReason.EndOfFile => "Unexpected end of file",
            ErrorReason.FileNameTooLong => "File name is too long",
            ErrorReason.FullVault => "Vault is full",
            ErrorReason.MissingChunk => "Missing chunk",
            ErrorReason.NoFreeSpace => "Not enough free space on disk",
            ErrorReason.NoReader => "Failed to find reader",
            ErrorReason.Other => "The operation could not be completed",
            ErrorReason.TaskFaulted => "One or more tasks failed",
            ErrorReason.WrongHMAC => "Wrong HMAC authentication tag",
            ErrorReason.EmptyFile => "Provided empty file",
            ErrorReason.OperationCancelled => "Operation cancelled by the user",
            ErrorReason.MaxRetriesReached => "Reached maximum amount of retries",
            _ => "Unknown error reason"
        };
    }
}
