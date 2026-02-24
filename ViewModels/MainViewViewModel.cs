using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;
using VaultCrypt.Services;

namespace VaultCrypt.ViewModels
{
    internal class MainViewViewModel : INotifyPropertyChanged, IViewModel, INavigatingViewModel
    {
        private readonly IFileDialogService _fileDialogService;
        public ICommand CreateVaultCommand { get; }
        public ICommand OpenVaultCommand { get; }

        internal MainViewViewModel(IFileDialogService fileDialogService)
        {
            _fileDialogService = fileDialogService;
            CreateVaultCommand = new RelayCommand(_ => NavigationRequested?.Invoke(new NavigateToCreateVaultRequest()));
            OpenVaultCommand = new RelayCommand(_ => SelectVaultFilePickerOpen());
        }

        internal void SelectVaultFilePickerOpen()
        {
            var dialog = _fileDialogService.OpenFile("Select vault file", false);
            if (dialog != null)
            {
                NavigationRequested?.Invoke(new NavigateToPasswordInputRequest(NormalizedPath.From(dialog)));
            }

        }



        private void OnPropertyChanged(string name) { PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name)); }
        public event PropertyChangedEventHandler? PropertyChanged;
        public event Action<NavigationRequest> NavigationRequested = null!;
    }
}
