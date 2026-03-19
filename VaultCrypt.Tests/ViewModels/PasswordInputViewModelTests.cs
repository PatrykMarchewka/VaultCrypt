using Microsoft.VisualBasic;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Exceptions;

namespace VaultCrypt.Tests.ViewModels
{
    public class PasswordInputViewModelTests
    {
        private VaultCrypt.ViewModels.PasswordInputViewModel _viewModel;

        public PasswordInputViewModelTests()
        {
            this._viewModel = new VaultCrypt.ViewModels.PasswordInputViewModel();
        }

        [Fact]
        void PasswordRaisesPropertyChanged()
        {
            string? changedProperty = null;
            _viewModel.PropertyChanged += (sender, args) => { changedProperty = args.PropertyName; };

            _viewModel.Password = new SecureString();

            Assert.Equal(nameof(_viewModel.Password), changedProperty);
        }

        [Fact]
        void PasswordDoesNotRaisePropertyChanged()
        {
            SecureString password = new SecureString();
            password.AppendChar('a');
            _viewModel.Password = password;
            int eventRaisedCount = 0;
            _viewModel.PropertyChanged += (sender, args) => { eventRaisedCount++; };
            _viewModel.Password = password;

            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        void PasswordChangesValues()
        {
            SecureString expected = new SecureString();
            expected.AppendChar('b');
            _viewModel.Password = expected;

            Assert.Equal(expected, _viewModel.Password);
        }

        [Fact]
        void OpenVaultRaisesNavigationRequest()
        {
            SecureString password = new SecureString();
            password.AppendChar('c');
            _viewModel.Password = password;

            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            _viewModel.OpenVault();
            Assert.Equal(1, eventRaisedCount);
        }

        [Fact]
        void OpenVaultDoesNotRaiseNavigationRequestAndThrows()
        {
            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            Assert.Throws<VaultUIException>(() => _viewModel.OpenVault());
            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        void NavigationRequestedRaised()
        {
            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            _viewModel.GoBackCommand.Execute(null);

            Assert.Equal(1, eventRaisedCount);
        }
    }
}
