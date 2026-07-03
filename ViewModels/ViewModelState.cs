using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Services;

namespace VaultCrypt.ViewModels
{
    internal static class ViewModelState
    {
        private static readonly DialogService dialogService = new DialogService();
        private static readonly EncryptionOptionsService encryptionOptionsService = new EncryptionOptionsService();
        private static readonly FileDialogService fileDialogService = new FileDialogService();
        private static readonly FileService fileService = new FileService();
        private static readonly NavigationService navigationService = new NavigationService();
        private static readonly SystemService systemService = new SystemService();
        private static readonly ExceptionHandlerService exceptionHandlerService = new ExceptionHandlerService(dialogService, navigationService);
        private static readonly EncryptionService encryptionService = new EncryptionService(fileService, encryptionOptionsService, systemService);
        private static readonly DecryptionService decryptionService = new DecryptionService(fileService, encryptionOptionsService, systemService);
        private static readonly VaultService vaultService = new VaultService(fileService, encryptionOptionsService, systemService);

        public static MainWindowViewModel MainWindow { get; } = new MainWindowViewModel();
        public static MainViewViewModel Main { get; } = new MainViewViewModel(fileDialogService);
        public static CreateVaultViewModel CreateVault { get; } = new CreateVaultViewModel(fileDialogService, vaultService);
        public static OpenVaultViewModel OpenVault { get; } = new OpenVaultViewModel(fileDialogService, vaultService, decryptionService, VaultSession.CurrentSession);
        public static PasswordInputViewModel PasswordInput { get; } = new PasswordInputViewModel();
        public static EncryptFileViewModel EncryptFile { get; } = new EncryptFileViewModel(encryptionService);
        public static ProgressViewModel Progress { get; } = new ProgressViewModel();
        public static ExceptionThrownViewModel ExceptionThrown { get; } = new ExceptionThrownViewModel();

        public static IEnumerable<IViewModel> AllViewModels
        {
            get
            {
                yield return MainWindow;
                yield return Main;
                yield return CreateVault;
                yield return OpenVault;
                yield return PasswordInput;
                yield return EncryptFile;
                yield return Progress;
                yield return ExceptionThrown;
            }
        }

        private static void SubscribeToGlobalEvents()
        {
            RelayCommand.SubscribeToExceptionThrowEvent((ex) => exceptionHandlerService.HandleException(ex));
            navigationService.SubscribeToChangeViewEvent((viewmodel) => MainWindow.CurrentView = viewmodel);
        }

        private static void InitializeNavigation()
        {
            foreach (var viewModel in ViewModelState.AllViewModels)
            {
                if (viewModel is INavigatingViewModel navigatingModel)
                {
                    navigatingModel.NavigationRequested += request => navigationService.HandleNavigation(request);
                }
            }
        }

        //Navigate to password input if provided valid path to vault file as argument
        private static void ResolveArguments(string[] args)
        {
            if (args.Length == 1 && NormalizedPath.ValidatePath(args[0], ensureExists: true)) navigationService.NavigateToPasswordInput(NormalizedPath.From(args[0]));
            else navigationService.NavigateToMain();
        }

        public static void OnStartup(string[] args)
        {
            SubscribeToGlobalEvents();
            InitializeNavigation();
            ResolveArguments(args);
        }
    }
}
