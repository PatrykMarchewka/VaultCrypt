using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.ViewModels;

namespace VaultCrypt.Services
{
    public interface INavigationService
    {
        public event Action<IViewModel> ChangeView;
        public void HandleNavigation(NavigationRequest request);
        public void NavigateToMain();
        public void NavigateToCreateVault();
        public void NavigateToOpenVault(SecureString password, NormalizedPath vaultPath);
        public void NavigateToPasswordInput(NormalizedPath vaultPath);
        public void NavigateToEncryptFile(NormalizedPath filePath);
        public void NavigateToProgress(ProgressionContext context);
        public void NavigateFromProgress();
        public void NavigateToExceptionThrown(Exception ex);

    }

    

    internal class NavigationService : INavigationService
    {
        private readonly ViewModelState viewModels;

        internal NavigationService(ViewModelState viewModels)
        {
            this.viewModels = viewModels;

            foreach (var viewModel in viewModels.AllViewModels)
            {
                if (viewModel is INavigatingViewModel navigatingModel)
                {
                    navigatingModel.NavigationRequested += request => this.HandleNavigation(request);
                }
            }
        }

        

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
            ChangeView?.Invoke(viewModel);
        }

        public void NavigateToMain()
        {
            VaultSession.CurrentSession.Dispose();
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

        public void NavigateToProgress(ProgressionContext context)
        {
            Navigate(viewModels.Progress, context);
        }

        public void NavigateFromProgress()
        {
            viewModels.OpenVault.RefreshCollection();
            Navigate(viewModels.OpenVault);
        }

        public void NavigateToExceptionThrown(Exception ex)
        {
            Navigate(viewModels.ExceptionThrown, ex);
        }
        public event Action<IViewModel> ChangeView = null!;
    }

    interface INavigated
    {
        public void OnNavigatedTo(object? parameters);
    }    
}
