namespace VaultCrypt.Services;

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