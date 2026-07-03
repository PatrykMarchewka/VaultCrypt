using System;
using System.Collections.Generic;
using System.IO;
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

        /// <summary>
        /// Validates <paramref name="filePath"/> by checking whether it points to a valid location, optionally checking if file exists at that location
        /// </summary>
        /// <param name="filePath">Path to check</param>
        /// <param name="ensureExists">Dictates whether to ensure that file exists at the provided <paramref name="filePath"/></param>
        /// <returns>True if every check is satisfied, otherwise false</returns>
        public static bool ValidatePath(NormalizedPath filePath, bool ensureExists = false)
        {
            if (!Path.IsPathRooted(filePath)) return false;
            if (ensureExists && !File.Exists(filePath)) return false;

            return true;
        }

        /// <inheritdoc cref="ValidatePath(NormalizedPath, bool)"/>
        public static bool ValidatePath(string filePath, bool ensureExists = false)
        {
            return ValidatePath(From(filePath), ensureExists);
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
