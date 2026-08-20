using System;
using System.IO;
using System.Threading.Tasks;
using VaultCrypt.Services;

namespace VaultCrypt.WPF.Services;

public sealed class FileDialogService : IFileDialogService
{
    public Task<string?> OpenFile(string title, bool allFiles)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = title,
            Filter = allFiles ? string.Empty : "Vault files (*.vlt)|*.vlt|All files (*.*)|*.*"
        };

        bool? result = dialog.ShowDialog();
        return Task.FromResult(result == true ? dialog.FileName : null);
    }

    public Task<string?> OpenFolder(string title)
    {
        var dialog = new Microsoft.Win32.OpenFolderDialog
        {
            Title = title
        };

        bool? result = dialog.ShowDialog();
        return Task.FromResult(result == true ? dialog.FolderName : null);
    }

    public Task<string?> SaveFile(string fileName)
    {
        //Gets extention without the dot
        string extension = Path.GetExtension(fileName) is string ext && ext.StartsWith(".") ? ext[1..] : "";

        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Choose where to save the file",
            FileName = fileName,
            AddExtension = false,
            DefaultExt = "",
            Filter = $"{extension.ToUpper()} files|*.{extension}|All files (*.*)|*.*",
            OverwritePrompt = true
        };

        bool? result = dialog.ShowDialog();

        if (dialog?.FileName.EndsWith(extension) == false) dialog.FileName += $".{extension}";
        return Task.FromResult(result == true ? dialog.FileName : null);
    }
}