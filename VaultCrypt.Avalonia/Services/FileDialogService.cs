using System.IO;
using VaultCrypt.Services;
using System.Threading.Tasks;
using Avalonia.Platform.Storage;

namespace VaultCrypt.Avalonia.Services;

public class FileDialogService : IFileDialogService
{

    public async Task<string?> OpenFile(string title, bool allFiles)
    {
        var currentWindow = WindowHelper.GetCurrentWindow();

        var files = await currentWindow.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions()
        {
            Title = title,
            FileTypeFilter = allFiles ? null : new[]
            {
                new FilePickerFileType("Vault files (*.vlt)") { Patterns = new[] { "*.vlt" } },
                FilePickerFileTypes.All
            }


        });
        return files.Count > 0 ? files[0].Path.LocalPath : null;
    }

    public async Task<string?> OpenFolder(string title)
    {
        var currentWindow = WindowHelper.GetCurrentWindow();

        var folders = await currentWindow.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions()
        {
            Title = title
        });
        
        return folders.Count > 0 ? folders[0].Path.OriginalString : null;
    }

    public async Task<string?> SaveFile(string fileName)
    {
        var currentWindow = WindowHelper.GetCurrentWindow();
        string extension = Path.GetExtension(fileName) is string e && e.StartsWith(".") ? e[1..] : "";

        var file = await currentWindow.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions()
        {
            Title = "Choose where to save the file",
            SuggestedFileName = fileName,
            FileTypeChoices = new[]
            {
                new FilePickerFileType($"{extension.ToUpper()} files") { Patterns = new[] { $"*.{extension}" } },
                FilePickerFileTypes.All
            },
            ShowOverwritePrompt = true
        });

        if (file is null) return null;
        
        string filePath = file.Path.LocalPath;
        if (!filePath.EndsWith(extension)) filePath += extension;
        return filePath;
    }
}