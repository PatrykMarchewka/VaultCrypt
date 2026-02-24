using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Services;

namespace VaultCrypt.ViewModels
{
    internal class ViewModelState
    {
        private static readonly FileDialogService fileDialogService = new FileDialogService();
        private static readonly FileService fileService = new FileService();
        private static readonly EncryptionOptionsService encryptionOptionsService = new EncryptionOptionsService(VaultSession.CurrentSession);
        private static readonly VaultService vaultService = new VaultService(fileService, VaultSession.CurrentSession, encryptionOptionsService);
        private static readonly EncryptionService encryptionService = new EncryptionService(fileService, encryptionOptionsService, VaultSession.CurrentSession);
        private static readonly DecryptionService decryptionService = new DecryptionService(fileService, encryptionOptionsService, VaultSession.CurrentSession);
        private static readonly VaultRegistry vaultRegistry = new VaultRegistry(VaultSession.CurrentSession, encryptionOptionsService);

        public MainWindowViewModel MainWindow { get; } = new MainWindowViewModel();
        public MainViewViewModel Main { get; } = new MainViewViewModel(fileDialogService);
        public CreateVaultViewModel CreateVault { get; } = new CreateVaultViewModel(fileDialogService, vaultService);
        public OpenVaultViewModel OpenVault { get; } = new OpenVaultViewModel(fileDialogService, vaultService, decryptionService, VaultSession.CurrentSession);
        public PasswordInputViewModel PasswordInput { get; } = new PasswordInputViewModel();
        public EncryptFileViewModel EncryptFile { get; } = new EncryptFileViewModel(encryptionService);
        public ProgressViewModel Progress { get; } = new ProgressViewModel();
        public ExceptionThrownViewModel ExceptionThrown { get; } = new ExceptionThrownViewModel();

        public IEnumerable<IViewModel> AllViewModels
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
    }
}
