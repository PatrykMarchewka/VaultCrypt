using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.ViewModels;

namespace VaultCrypt.Tests.ViewModels
{
    public class PasswordInputViewModelTests
    {
        private readonly VaultCrypt.ViewModels.PasswordInputViewModel _viewModel = new PasswordInputViewModel();

        private ISecureBuffer? GetPasswordBuffer()
        {
            return (ISecureBuffer?)_viewModel.GetType().GetField("_passwordBuffer", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!.GetValue(_viewModel);
        }

        [Fact]
        internal void PasswordStringRaisesPropertyChanged()
        {
            string? changedProperty = null;
            _viewModel.PropertyChanged += (sender, args) => { changedProperty = args.PropertyName; };

            _viewModel.PasswordString = "RaisedProperty";

            Assert.Equal(nameof(_viewModel.PasswordString), changedProperty);
        }

        [Fact]
        internal void PasswordStringDoesNotRaisePropertyChanged()
        {
            string value = "DoesntRaiseProperty";
            _viewModel.PasswordString = value;
            int eventRaisedCount = 0;
            _viewModel.PropertyChanged += (sender, args) => { eventRaisedCount++; };
            _viewModel.PasswordString = value;

            Assert.Equal(0, eventRaisedCount);
        }

        [Fact]
        internal void PasswordStringChangesValue()
        {
            string expected = "ChangedValue";
            _viewModel.PasswordString = expected;

            Assert.Equal(expected, _viewModel.PasswordString);
        }

        [Fact]
        internal void GoBackRaisesNavigationRequest()
        {
            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += request => eventRaisedCount++;
            _viewModel.GoBack();
            Assert.Equal(1, eventRaisedCount);
        }

        [Fact]
        internal void OpenVaultRaisesNavigationRequest()
        {
            _viewModel.PasswordString = "Testing";
            try
            {
                int eventRaisedCount = 0;
                _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
                _viewModel.OpenVault();
                Assert.Equal(1, eventRaisedCount);
            }
            finally
            {
                GetPasswordBuffer()?.Dispose();
            }
        }
        
        [Fact]
        internal void OpenVaultDoesNotRaiseNavigationRequestAndThrows()
        {
            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            Assert.Throws<VaultCrypt.Exceptions.VaultUIException>(() => _viewModel.OpenVault());
            Assert.Equal(0, eventRaisedCount);
        }
        
        [Fact]
        internal void OpenVaultSetsBufferCorrectly()
        {
            _viewModel.PasswordString = "newPassword";
            byte[] predeterminedStringValue = new byte[] { 110, 0, 101, 0, 119, 0, 80, 0, 97, 0, 115, 0, 115, 0, 119, 0, 111, 0, 114, 0, 100, 0 }; //newPassword
            _viewModel.NavigationRequested += request => { }; //Required to avoid failure due to lack of bindings
            
            try
            {
                _viewModel.OpenVault(); //Always fails due to lack of bindings for navigation
                var buffer = GetPasswordBuffer();
                Assert.True(buffer!.AsSpan.SequenceEqual(predeterminedStringValue));
            }
            finally
            {
                GetPasswordBuffer()?.Dispose();   
            }
        }

        [Fact]
        internal void OpenVaultClearsPasswordString()
        {
            _viewModel.PasswordString = "newPassword";
            _viewModel.NavigationRequested += request => { }; //Required to avoid failure due to lack of bindings
            try
            {
                _viewModel.OpenVault();
                Assert.Empty(_viewModel.PasswordString);
            }
            finally
            {
                GetPasswordBuffer()?.Dispose();
            }
        }
        
        [Theory]
        [MemberData(nameof(TestsHelper.InvalidStrings), MemberType = typeof(TestsHelper))]
        internal void OpenVaultThrowsForInvalidPasswordString(string password, Type _)
        {
            _viewModel.PasswordString = password;
            Assert.Throws<VaultCrypt.Exceptions.VaultUIException>(() => _viewModel.OpenVault());
        }

        [Fact]
        internal void OnNavigatedToSetsValues()
        {
            NormalizedPath expected = NormalizedPath.From("OnNavigatedToTest");

            _viewModel.OnNavigatedTo(expected);

            //Reflection because _viewmodel._vaultPath is private
            //TODO: Replace reflection with something better
            NormalizedPath actual = (NormalizedPath)_viewModel.GetType().GetField("_vaultPath", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!.GetValue(_viewModel)!;

            Assert.Equal(expected, actual);
        }

        public static TheoryData<object?, Type> InvalidParameters = new TheoryData<object?, Type>()
        {
            {null, typeof(ArgumentNullException) },
            {new(), typeof(ArgumentException) },
            {NormalizedPath.From(""), typeof(ArgumentException) },
            {NormalizedPath.From("  "), typeof(ArgumentException) }
        };

        [Theory]
        [MemberData(nameof(InvalidParameters))]
        internal void OnNavigatedToThrowsForInvalidParameters(object? parameters, Type expectedException)
        {
            Assert.Throws(expectedException, () => _viewModel.OnNavigatedTo(parameters!));
        }
        
        [Fact]
        internal void NavigationRequestedRaised()
        {
            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            _viewModel.GoBackCommand.Execute(null);

            Assert.Equal(1, eventRaisedCount);
        }
    }
}
