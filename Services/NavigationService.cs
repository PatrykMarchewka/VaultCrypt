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
        /// <summary>
        /// Event to invoke when switching views
        /// </summary>
        public event Action<IViewModel> ChangeView;
        /// <summary>
        /// Used by viewmodels only to process <paramref name="request"/> and invoke navigation
        /// </summary>
        /// <param name="request">Request to invoke</param>
        public void HandleNavigation(NavigationRequest request);
        /// <summary>
        /// Disposes current session and navigates to <see cref="ViewModels.MainViewViewModel"/>
        /// </summary>
        public void NavigateToMain();
        /// <summary>
        /// Navigates to <see cref="ViewModels.CreateVaultViewModel"/>
        /// </summary>
        public void NavigateToCreateVault();
        /// <summary>
        /// Navigates to <see cref="ViewModels.OpenVaultViewModel"/>
        /// </summary>
        /// <param name="password">Password to try open vault with</param>
        /// <param name="vaultPath">Path to the vault file</param>
        public void NavigateToOpenVault(SecureString password, NormalizedPath vaultPath);
        /// <summary>
        /// Naivates to <see cref="ViewModels.PasswordInputViewModel"/>
        /// </summary>
        /// <param name="vaultPath">Path to the vault file</param>
        public void NavigateToPasswordInput(NormalizedPath vaultPath);
        /// <summary>
        /// Navigates to <see cref="ViewModels.EncryptFileViewModel"/>
        /// </summary>
        /// <param name="filePath">Path of the file to encrypt</param>
        public void NavigateToEncryptFile(NormalizedPath filePath);
        /// <summary>
        /// Navigates to <see cref="ViewModels.ProgressViewModel"/>
        /// </summary>
        /// <param name="context">Context to pass in order to display progression</param>
        public void NavigateToProgress(ProgressionContext context);
        /// <summary>
        /// Navigates back from <see cref="ViewModels.ProgressViewModel"/>
        /// </summary>
        public void NavigateFromProgress();
        /// <summary>
        /// Navigates to <see cref="ViewModels.ExceptionThrownViewModel"/>
        /// </summary>
        /// <param name="ex">Thrown exception to display</param>
        public void NavigateToExceptionThrown(Exception ex);

    }

    

    internal class NavigationService : INavigationService
    {
        private readonly IVaultSession _session;

        internal NavigationService(IVaultSession session)
        {
            this._session = session;

            foreach (var viewModel in ViewModelState.AllViewModels)
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
            _session.Dispose();
            Navigate(ViewModelState.Main);
        }

        public void NavigateToCreateVault()
        {
            Navigate(ViewModelState.CreateVault);
        }

        public void NavigateToOpenVault(SecureString password, NormalizedPath vaultPath)
        {
            Navigate(ViewModelState.OpenVault, new { Password = password, VaultPath = vaultPath });
        }

        public void NavigateToPasswordInput(NormalizedPath vaultPath)
        {
            Navigate(ViewModelState.PasswordInput, vaultPath);
        }

        public void NavigateToEncryptFile(NormalizedPath filePath)
        {
            Navigate(ViewModelState.EncryptFile, filePath);
        }

        public void NavigateToProgress(ProgressionContext context)
        {
            Navigate(ViewModelState.Progress, context);
        }

        public void NavigateFromProgress()
        {
            ViewModelState.OpenVault.RefreshCollection();
            Navigate(ViewModelState.OpenVault);
        }

        public void NavigateToExceptionThrown(Exception ex)
        {
            Navigate(ViewModelState.ExceptionThrown, ex);
        }
        public event Action<IViewModel> ChangeView = null!;
    }

    interface INavigated
    {
        public void OnNavigatedTo(object? parameters);
    }    
}
