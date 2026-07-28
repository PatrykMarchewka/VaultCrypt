using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Exceptions
{
    public sealed class VaultUIException : Exception
    {
        internal VaultUIException(string message) : base(message) { }
    }
}
