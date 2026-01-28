using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Exceptions;

namespace VaultCrypt
{
    internal static class ValidationHelper
    {
        internal static void NotEmptyString(string? input, string fieldName)
        {
            if (string.IsNullOrWhiteSpace(input)) throw new VaultUIException($"{fieldName} cannot be empty");
        }

        internal static void NotEmptySecureString(SecureString? input, string fieldName)
        {
            if (input is null || input.Length == 0) throw new VaultUIException($"{fieldName} cannot be empty");
        }
    }
}
