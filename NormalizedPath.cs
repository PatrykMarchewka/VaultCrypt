using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt
{
    public class NormalizedPath
    {
        public string Value { get; }
        private NormalizedPath(string path)
        {
            Value = Normalize(path);
        }
        private static string Normalize(string path)
        {
            return path.Length > 260 && !path.StartsWith(@"\\?\") ? @"\\?\" + path : path;
        }

        /// <summary>
        /// Normalizes string and returns it as NormalizedPath
        /// </summary>
        /// <param name="input">String to normalize</param>
        /// <returns>NormalizedPath containing the path from the input</returns>
        /// <exception cref="ArgumentNullException">Thrown when provided <paramref name="input"/> is set to null</exception>
        public static NormalizedPath From(string input)
        {
            ArgumentNullException.ThrowIfNull(input);
            return new NormalizedPath(input);
        }

        //Required to use string interpolation like $"{normalizedPath}"
        public override string ToString() => Value;

        public static implicit operator string(NormalizedPath path)
        {
            ArgumentNullException.ThrowIfNull(path);
            return path.Value;
        }
    }
}
