using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Exceptions
{
    public abstract class VaultException : Exception
    {
        public ErrorReason ExceptionReason { get; }

        protected VaultException(string context, ErrorReason reason, Exception? innerException = null) : base($"{context}: {GetReason(reason)}", innerException) {
            ExceptionReason = reason;
        }

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

    public class VaultEncryptionException : VaultException
    {
        public VaultEncryptionException(ErrorReason reason, Exception? innerException = null) : base("Encryption failed", reason, innerException) { }
    }

    public class VaultDecryptionException : VaultException
    {
        public VaultDecryptionException(ErrorReason reason, Exception? innerException = null) : base("Decryption failed", reason, innerException) { }
    }

    public class VaultEncryptionOptionsOperationException : VaultException
    {
        public VaultEncryptionOptionsOperationException(ErrorReason reason, Exception? innerException = null) : base("Encryption options operation failed", reason, innerException) { }
    }

    public class VaultSystemCheckException : VaultException
    {
        public VaultSystemCheckException(ErrorReason reason, Exception? innerException = null) : base("System check failed", reason, innerException) { }
    }

    public class VaultOperationException : VaultException
    {
        public VaultOperationException(ErrorReason reason, Exception? innerException = null) : base("Vault operation failed", reason, innerException) { }
    }

    public class VaultIOOperationException : VaultException
    {
        public VaultIOOperationException(ErrorReason reason, Exception? innerException = null) : base("Writing to file failed", reason, innerException) { }
    }
}
