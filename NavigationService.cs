using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt
{
    interface INavigationService
    {
        void NavigateToMain();
        void NavigateToCreateVault();
        void NavigateToOpenVault(SecureString password, string vaultPath);
        void NavigateToPasswordInput(string vaultPath);
    }

    interface INavigated
    {
        void OnNavigatedTo(object? parameters);
    }
}
