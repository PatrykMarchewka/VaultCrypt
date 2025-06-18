using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt
{
    internal class FileHelper
    {
        public static string NormalizePath(string path)
        {
            return path.Length > 260 ? @"\\?\" + path : path;
        }
        public static void DeleteFileSecurely(string filepath, int overwrites = 3)
        {
            if (!File.Exists(filepath)) return;

            using (FileStream fs = new FileStream(filepath,FileMode.Open,FileAccess.Write))
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









    }
}
