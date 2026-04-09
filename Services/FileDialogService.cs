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
        /// <summary>
        /// Opens file dialog window
        /// </summary>
        /// <param name="title">Title of the window</param>
        /// <param name="allFiles">Indicates whether to show all files or just vault files</param>
        /// <returns>String containing the full filepath of selected file</returns>
        public string? OpenFile(string title, bool allFiles);
        /// <summary>
        /// Opens folder dialog window
        /// </summary>
        /// <param name="title">Title of the window</param>
        /// <returns>String containing the full path to the selected folder</returns>
        public string? OpenFolder(string title);
        /// <summary>
        /// Opens save file dialog window
        /// </summary>
        /// <param name="fileName">Original name of file to save</param>
        /// <returns>String containing the full filepath</returns>
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
            string extension = Path.GetExtension(fileName).TrimStart('.');

            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Choose where to save the file",
                FileName = fileName,
                AddExtension = false,
                DefaultExt = "",
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
