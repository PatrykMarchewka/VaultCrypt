using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Services;

namespace VaultCrypt.ViewModels
{
    public static class ViewModelState
    {
        //Services
        private static IDialogService _dialogService { get; set; }
        private static IFileDialogService _fileDialogService { get; set; }
        private static EncryptionOptionsService _encryptionOptionsService { get; set; }
        private static FileService _fileService { get; set; }
        private static NavigationService _navigationService { get; set; }
        private static SystemService _systemService { get; set; }
        private static ExceptionHandlerService _exceptionHandlerService { get; set; }
        private static EncryptionService _encryptionService { get; set; }
        private static DecryptionService _decryptionService { get; set; }
        private static VaultService _vaultService { get; set; }
        private static bool _servicesInitialized = false;

        //Viewmodels
        public static MainWindowViewModel MainWindow { get; set; }
        public static MainViewViewModel Main { get; set; }
        public static CreateVaultViewModel CreateVault { get; set; }
        public static OpenVaultViewModel OpenVault { get; set; }
        public static PasswordInputViewModel PasswordInput { get; set; }
        public static EncryptFileViewModel EncryptFile { get; set; }
        public static ProgressViewModel Progress { get; set; }
        public static ExceptionThrownViewModel ExceptionThrown { get; set; }
        private static bool _viewmodelsInitialized = false;

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
        
        private static void InitializeServices(IDialogService dialogService, IFileDialogService fileDialogService)
        {
            _dialogService = dialogService;
            _fileDialogService = fileDialogService;
            _encryptionOptionsService = new EncryptionOptionsService();
            _fileService = new FileService();
            _navigationService = new NavigationService();
            _systemService = new SystemService();
            _exceptionHandlerService = new ExceptionHandlerService(_dialogService, _navigationService);
            _encryptionService = new EncryptionService(_fileService, _encryptionOptionsService, _systemService);
            _decryptionService = new DecryptionService(_fileService, _encryptionOptionsService, _systemService);
            _vaultService = new VaultService(_fileService, _encryptionOptionsService, _systemService);
            
            _servicesInitialized = true;
        }

        private static void InitializeViewModels()
        {
            if (!_servicesInitialized) throw new InvalidOperationException("Services need to be initialized before viewmodels");

            MainWindow = new MainWindowViewModel();
            Main = new MainViewViewModel(_fileDialogService);
            CreateVault = new CreateVaultViewModel(_fileDialogService, _vaultService);
            OpenVault = new OpenVaultViewModel(_fileDialogService, _vaultService, _decryptionService, VaultSession.CurrentSession);
            PasswordInput = new PasswordInputViewModel();
            EncryptFile = new EncryptFileViewModel(_encryptionService);
            Progress = new ProgressViewModel();
            ExceptionThrown = new ExceptionThrownViewModel();

            _viewmodelsInitialized = true;
        }

        private static void SubscribeToGlobalEvents()
        {
            RelayCommand.SubscribeToExceptionThrowEvent((ex) => _exceptionHandlerService.HandleException(ex));
            _navigationService.SubscribeToChangeViewEvent((viewmodel) => MainWindow.CurrentView = viewmodel);
        }

        private static void InitializeNavigation()
        {
            foreach (var viewModel in ViewModelState.AllViewModels)
            {
                if (viewModel is INavigatingViewModel navigatingModel)
                {
                    navigatingModel.NavigationRequested += request => _navigationService.HandleNavigation(request);
                }
            }
        }

        //Navigate to password input if provided valid path to vault file as argument
        private static void ResolveArguments(string[]? args)
        {
            if (args?.Length == 1 && NormalizedPath.ValidatePath(args[0], ensureExists: true)) _navigationService.NavigateToPasswordInput(NormalizedPath.From(args[0]));
            else _navigationService.NavigateToMain();
        }

        /// <summary>
        /// Initializes services, creates viewmodels and binds navigation
        /// </summary>
        /// <param name="args">Commandline arguments to pass</param>
        /// <param name="dialogService">Dialog service with information about window to show when <see cref="Exceptions.VaultUIException"/> is thrown </param>
        /// <param name="fileDialogService">Dialog service with information about window to show when needing to pick file or folder from disk</param>
        public static void OnStartup(string[]? args, IDialogService dialogService, IFileDialogService fileDialogService)
        {
            InitializeServices(dialogService, fileDialogService);
            InitializeViewModels();
            SubscribeToGlobalEvents();
            InitializeNavigation();
            ResolveArguments(args);
        }
    }
}
