using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Tests.Services;

namespace VaultCrypt.Tests.ViewModels
{
    public class MainViewViewModelTests
    {
        private VaultCrypt.ViewModels.MainViewViewModel _viewModel;

        public MainViewViewModelTests()
        {
            this._viewModel = new VaultCrypt.ViewModels.MainViewViewModel(new FakeFileDialogService());
        }

        private void CreateVMWithFileDialogService(string? returnValue)
        {
            this._viewModel = new VaultCrypt.ViewModels.MainViewViewModel(new FakeFileDialogService() { ReturnValue = returnValue });
        }

        [Fact]
        void SelectVaultFileRaisesNavigationRequest()
        {
            int eventRaisedCount = 0;
            CreateVMWithFileDialogService("not null");
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            _viewModel.SelectVaultFile();

            Assert.Equal(1, eventRaisedCount);
        }

        [Fact]
        void SelectVaultFileDoesNotRaiseNavigationRequest()
        {
            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            _viewModel.SelectVaultFile();

            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        void NavigationRequestedRaised()
        {
            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            _viewModel.CreateVaultCommand.Execute(null);

            Assert.Equal(1, eventRaisedCount);
        }
    }
}
