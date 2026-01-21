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
    
    internal class NavigationService : INavigationService
    {
        public void HandleNavigation(NavigationRequest navigationRequest)
        {
            navigationRequest.Request(this);
        }
        private void Navigate(IViewModel viewModel, object? parameters = null)
        {
            if (viewModel is INavigated nav && parameters != null)
            {
                nav.OnNavigatedTo(parameters);
            }
            NavigateEvent?.Invoke(viewModel);
        }

        public void NavigateToMain()
        {
            VaultSession.Dispose();
            Navigate(viewModels.Main);
        }

        public void NavigateToCreateVault()
        {
            Navigate(viewModels.CreateVault);
        }

        public void NavigateToOpenVault(SecureString password, NormalizedPath vaultPath)
        {
            Navigate(viewModels.OpenVault, new { Password = password, VaultPath = vaultPath });
        }

        public void NavigateToPasswordInput(NormalizedPath vaultPath)
        {
            Navigate(viewModels.PasswordInput, vaultPath);
        }

        public void NavigateToEncryptFile(NormalizedPath filePath)
        {
            Navigate(viewModels.EncryptFile, filePath);
        }

        public void NavigateToProgress(VaultHelper.ProgressionContext context)
        {
            Navigate(viewModels.Progress, context);
        }

        public void NavigateFromProgress()
        {
            using var vaultFS = new FileStream(VaultSession.VAULTPATH, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            VaultHelper.RefreshEncryptedFilesList(vaultFS);
            Navigate(viewModels.OpenVault);
        }
    }

    interface INavigated
    {
        void OnNavigatedTo(object? parameters);
    }    
}
