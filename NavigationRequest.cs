using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Services;

namespace VaultCrypt
{

    internal abstract record NavigationRequest
    {
        internal abstract void Request(INavigationService nav);
    }

    internal sealed record NavigateToMainRequest : NavigationRequest
    {
        internal override void Request(INavigationService nav) => nav.NavigateToMain();
    }

    internal sealed record NavigateToCreateVaultRequest : NavigationRequest
    {
        internal override void Request(INavigationService nav) => nav.NavigateToCreateVault();
    }

    internal sealed record NavigateToOpenVaultRequest(SecureString password, NormalizedPath vaultPath) : NavigationRequest
    {
        internal override void Request(INavigationService nav) => nav.NavigateToOpenVault(password, vaultPath);
    }

    internal sealed record NavigateToPasswordInputRequest(NormalizedPath vaultPath) : NavigationRequest
    {
        internal override void Request(INavigationService nav) => nav.NavigateToPasswordInput(vaultPath);
    }

    internal sealed record NavigateToEncryptFileRequest(NormalizedPath filePath) : NavigationRequest
    {
        internal override void Request(INavigationService nav) => nav.NavigateToEncryptFile(filePath);
    }

    internal sealed record NavigateToProgressRequest(VaultHelper.ProgressionContext context) : NavigationRequest
    {
        internal override void Request(INavigationService nav) => nav.NavigateToProgress(context);
    }

    internal sealed record NavigateFromProgressRequest : NavigationRequest
    {
        internal override void Request(INavigationService nav) => nav.NavigateFromProgress();
    }

    internal sealed record NavigateToExceptionThrownRequest(Exception ex) : NavigationRequest
    {
        internal override void Request(INavigationService nav) => nav.NavigateToExceptionThrown(ex);
    }
}
