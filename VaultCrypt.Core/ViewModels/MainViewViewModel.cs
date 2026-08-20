using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;
using VaultCrypt.Services;

namespace VaultCrypt.ViewModels
{
    public class MainViewViewModel : INavigatingViewModel
    {
        private readonly IFileDialogService _fileDialogService;

        public ICommand CreateVaultCommand { get; }
        public ICommand OpenVaultCommand { get; }

        public string ApplicationVersion => Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "Unknown version";

        public MainViewViewModel(IFileDialogService fileDialogService)
        {
            ArgumentNullException.ThrowIfNull(fileDialogService);

            this._fileDialogService = fileDialogService;
            CreateVaultCommand = new RelayCommand(_ => NavigationRequested?.Invoke(new NavigateToCreateVaultRequest()));
            OpenVaultCommand = new RelayCommand(_ => SelectVaultFile());
        }

        public async Task SelectVaultFile()
        {
            var dialog = await _fileDialogService.OpenFile("Select vault file", false);
            if (dialog != null)
            {
                NavigationRequested?.Invoke(new NavigateToPasswordInputRequest(NormalizedPath.From(dialog)));
            }
        }

        public event Action<NavigationRequest> NavigationRequested = null!;
    }
}
