using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Services;

namespace VaultCrypt
{

    public abstract record NavigationRequest
    {
        public abstract void Request(INavigationService nav);
    }

    public sealed record NavigateToMainRequest : NavigationRequest
    {
        public override void Request(INavigationService nav) => nav.NavigateToMain();
    }

    public sealed record NavigateToCreateVaultRequest : NavigationRequest
    {
        public override void Request(INavigationService nav) => nav.NavigateToCreateVault();
    }

    public sealed record NavigateToOpenVaultRequest(SecureString password, NormalizedPath vaultPath) : NavigationRequest
    {
        public override void Request(INavigationService nav) => nav.NavigateToOpenVault(password, vaultPath);
    }

    public sealed record NavigateToPasswordInputRequest(NormalizedPath vaultPath) : NavigationRequest
    {
        public override void Request(INavigationService nav) => nav.NavigateToPasswordInput(vaultPath);
    }

    public sealed record NavigateToEncryptFileRequest(NormalizedPath filePath) : NavigationRequest
    {
        public override void Request(INavigationService nav) => nav.NavigateToEncryptFile(filePath);
    }

    public sealed record NavigateToProgressRequest(ProgressionContext context) : NavigationRequest
    {
        public override void Request(INavigationService nav) => nav.NavigateToProgress(context);
    }

    public sealed record NavigateFromProgressRequest : NavigationRequest
    {
        public override void Request(INavigationService nav) => nav.NavigateFromProgress();
    }

    public sealed record NavigateToExceptionThrownRequest(Exception ex) : NavigationRequest
    {
        public override void Request(INavigationService nav) => nav.NavigateToExceptionThrown(ex);
    }
}
