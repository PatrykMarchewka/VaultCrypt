namespace VaultCrypt.Services;

public interface IDialogService
{
    /// <summary>
    /// Shows new window with information about the <paramref name="ex"/>
    /// </summary>
    /// <param name="ex">Exception to show</param>
    public void ShowErrorWindow(Exception ex);
}