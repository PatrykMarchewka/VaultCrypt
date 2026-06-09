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
        private readonly VaultCrypt.ViewModels.PasswordInputViewModel _viewModel;

        public PasswordInputViewModelTests()
        {
            this._viewModel = new VaultCrypt.ViewModels.PasswordInputViewModel();
        }

        private ISecureBuffer SetPasswordBuffer(ISecureBuffer buffer)
        {
            _viewModel.GetType().GetField("_passwordBuffer", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!.SetValue(_viewModel, buffer);
            return buffer;
        }

        private ISecureBuffer SetPasswordBuffer()
        {
            SecureBuffer.SecureKeyBuffer keyBuffer = new SecureBuffer.SecureKeyBuffer(1);
            return SetPasswordBuffer(keyBuffer);
        }

        [Fact]
        internal void OpenVaultRaisesNavigationRequest()
        {
            ISecureBuffer buffer = null!;
            try
            {
                buffer = SetPasswordBuffer();
                int eventRaisedCount = 0;
                _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
                _viewModel.OpenVault();
                Assert.Equal(1, eventRaisedCount);
            }
            finally
            {
                buffer.Dispose();
            }
        }

        [Fact]
        internal void OpenVaultDoesNotRaiseNavigationRequestAndThrows()
        {
            int eventRaisedCount = 0;
            _viewModel.NavigationRequested += (request) => { eventRaisedCount++; };
            Assert.Throws<VaultUIException>(() => _viewModel.OpenVault());
            Assert.Equal(0, eventRaisedCount);
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

        [Fact]
        internal void RecievePasswordStringSetsBufferCorrectly()
        {
            byte[] predeterminedStringValue = new byte[] { 110, 0, 101, 0, 119, 0, 80, 0, 97, 0, 115, 0, 115, 0, 119, 0, 111, 0, 114, 0, 100, 0 }; //newPassword
            _viewModel.RecievePasswordString("newPassword");
            var newBuffer = (ISecureBuffer)_viewModel.GetType().GetField("_passwordBuffer", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!.GetValue(_viewModel)!;

            Assert.True(newBuffer.AsSpan.SequenceEqual(predeterminedStringValue));
        }

        [Theory]
        [MemberData(nameof(TestsHelper.InvalidStrings), MemberType = typeof(TestsHelper))]
        internal void RecievePasswordStringThrowsForInvalidString(string password, Type expectedException)
        {
            Assert.Throws(expectedException, () => _viewModel.RecievePasswordString(password));
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
