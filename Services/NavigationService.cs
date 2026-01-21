using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Services
{
    interface INavigationService
    {
        void HandleNavigation(NavigationRequest request);
        void NavigateToMain();
        void NavigateToCreateVault();
        void NavigateToOpenVault(SecureString password, NormalizedPath vaultPath);
        void NavigateToPasswordInput(NormalizedPath vaultPath);
        void NavigateToEncryptFile(NormalizedPath filePath);
        void NavigateToProgress(VaultHelper.ProgressionContext context);
        void NavigateFromProgress();
    }
    
    interface INavigated
    {
        void OnNavigatedTo(object? parameters);
    }    
}
