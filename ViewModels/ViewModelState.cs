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

        public MainWindowViewModel MainWindow { get; } = new MainWindowViewModel();
        public MainViewViewModel Main { get; } = new MainViewViewModel(fileDialogService);
        public CreateVaultViewModel CreateVault { get; } = new CreateVaultViewModel(fileDialogService);
        public OpenVaultViewModel OpenVault { get; } = new OpenVaultViewModel(fileDialogService);
        public PasswordInputViewModel PasswordInput { get; } = new PasswordInputViewModel();
        public EncryptFileViewModel EncryptFile { get; } = new EncryptFileViewModel();
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
