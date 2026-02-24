using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Services
{
    public interface IFileDialogService
    {
        public string? OpenFile(string title, bool allFiles);
        public string? OpenFolder(string title);
        public string? SaveFile(string fileName);
    }


    public class FileDialogService : IFileDialogService
    {
        public string? OpenFile(string title, bool allFiles)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = title,
                Filter = allFiles == true ? string.Empty : "Vault files (*.vlt)|*.vlt|All files (*.*)|*.*"
            };

            if (dialog.ShowDialog() == true)
            {
                return dialog.FileName;
            }
            return null;
        }

        public string? OpenFolder(string title)
        {
            var dialog = new Microsoft.Win32.OpenFolderDialog
            {
                Title = title
            };

            if (dialog.ShowDialog() == true)
            {
                return dialog.FolderName;
            }
            return null;
        }

        public string? SaveFile(string fileName)
        {
            string name = Path.GetFileNameWithoutExtension(fileName);
            string extension = Path.GetExtension(fileName).TrimStart('.');

            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Choose where to save the file",
                FileName = name,
                DefaultExt = extension,
                Filter = $"{extension.ToUpper()} files|*.{extension}|All files (*.*)|*.*",
                OverwritePrompt = true
            };

            if (dialog.ShowDialog() == true)
            {
                return dialog.FileName;
            }
            return null;
        }
    }
}
