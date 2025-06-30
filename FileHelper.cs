using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Printing.IndexedProperties;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt
{
    internal class FileHelper
    {
        
        public static void DeleteFileSecurely(NormalizedPath filepath, int overwrites = 3)
        {
            if (!File.Exists(filepath)) return;

            using (FileStream fs = new FileStream(filepath, FileMode.Open,FileAccess.Write))
            {
                byte[] data = new byte[fs.Length];

                for (int i = 0; i < overwrites; i++)
                {
                    new Random().NextBytes(data);
                    fs.Seek(0, SeekOrigin.Begin);
                    fs.Write(data, 0, data.Length);
                    fs.Flush();
                }

            }
            File.Delete(filepath);
        }

        public static void DeleteBytesSecurely(long offset, long bytes, int overwrites = 3)
        {
            using (FileStream fs = new FileStream(VaultInfo.vaultPath,FileMode.Open, FileAccess.Write))
            {
                byte[] data = new byte[bytes];

                for (int i = 0; i < overwrites; i++)
                {
                    new Random().NextBytes(data);
                    fs.Seek(offset, SeekOrigin.Begin);
                    fs.Write(data, 0, data.Length);
                    fs.Flush();
                }
            }
        }









    }


    public class NormalizedPath
    {
        public string Value { get; }
        private NormalizedPath(string path)
        {
            Value = Normalize(path);
        }
        public static string Normalize(string path)
        {
            return path.Length > 260 && !path.StartsWith(@"\\?\") ? @"\\?\" + path : path;
        }

        public static NormalizedPath From(string input) => new NormalizedPath(input);

        public override string ToString()
        {
            return Value;
        }

        public static implicit operator string(NormalizedPath path) => path.Value;


    }





}
