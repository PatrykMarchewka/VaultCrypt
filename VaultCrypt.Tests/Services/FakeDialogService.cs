using VaultCrypt.Services;

namespace VaultCrypt.Tests.Services;

public class FakeDialogService : IDialogService
{
    public bool ShowErrorWindowWasCalled = false;

    public void ShowErrorWindow(Exception ex) => ShowErrorWindowWasCalled = true;
}