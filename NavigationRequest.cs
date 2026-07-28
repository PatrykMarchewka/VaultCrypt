using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Services;

namespace VaultCrypt
{

    public abstract class NavigationRequest
    {
        public abstract void Request(INavigationService nav);
    }

    public sealed class NavigateToMainRequest : NavigationRequest
    {
        public override void Request(INavigationService nav) => nav.NavigateToMain();
    }

    public sealed class NavigateToCreateVaultRequest : NavigationRequest
    {
        public override void Request(INavigationService nav) => nav.NavigateToCreateVault();
    }

    public sealed class NavigateToOpenVaultRequest(ISecureBuffer password, NormalizedPath vaultPath) : NavigationRequest
    {
        public override void Request(INavigationService nav) => nav.NavigateToOpenVault(password, vaultPath);
    }

    public sealed class NavigateToPasswordInputRequest(NormalizedPath vaultPath) : NavigationRequest
    {
        public override void Request(INavigationService nav) => nav.NavigateToPasswordInput(vaultPath);
    }

    public sealed class NavigateToEncryptFileRequest(NormalizedPath filePath) : NavigationRequest
    {
        public override void Request(INavigationService nav) => nav.NavigateToEncryptFile(filePath);
    }

    public sealed class NavigateToProgressRequest(ProgressionContext context) : NavigationRequest
    {
        public override void Request(INavigationService nav) => nav.NavigateToProgress(context);
    }

    public sealed class NavigateFromProgressRequest : NavigationRequest
    {
        public override void Request(INavigationService nav) => nav.NavigateFromProgress();
    }

    public sealed class NavigateToExceptionThrownRequest(VaultCrypt.Exceptions.VaultException ex) : NavigationRequest
    {
        public override void Request(INavigationService nav) => nav.NavigateToExceptionThrown(ex);
    }
}
