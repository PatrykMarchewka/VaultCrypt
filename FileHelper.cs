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

        /// <summary>
        /// Checks whether there is enough free space to perform operation
        /// </summary>
        /// <param name="path">Path of the folder/file to check</param>
        /// <returns>True if there is enough space, otherwise false</returns>
        /// <exception cref="Exception">File/folder can't be located</exception>
        public static bool CheckFreeSpace(NormalizedPath path)
        {            
            long availableBytes = new DriveInfo(Path.GetPathRoot(path)).AvailableFreeSpace;

            return availableBytes > (GetTotalBytes(path) * 1.05);
        }

        public static long GetTotalBytes(NormalizedPath path)
        {
            if (File.Exists(path))
            {
                return new FileInfo(path).Length;

            }
            else if (Directory.Exists(path))
            {
                return Directory.GetFiles(path, "*", SearchOption.AllDirectories).Select(f => new FileInfo(f).Length).Sum();
            }
            else
            {
                throw new Exception("Cant find the file/folder");
            }
        }

        public static uint GetChunkNumber(NormalizedPath path, int chunkSizeMB = 256)
        {
            chunkSizeMB *= (1024 * 1024);
            return (uint)Math.Ceiling((double)GetTotalBytes(path) / chunkSizeMB);
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
