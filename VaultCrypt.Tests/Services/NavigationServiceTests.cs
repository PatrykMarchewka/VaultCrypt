using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Services;
using VaultCrypt.ViewModels;

namespace VaultCrypt.Tests.Services
{
    public class NavigationServiceTests
    {
        private readonly NavigationService _navigationService = new();

        [Fact]
        internal void HandleNavigationThrowsForInvalidValues()
        {
            Assert.Throws<ArgumentNullException>(() => _navigationService.HandleNavigation(null!));
        }

        [Fact]
        internal void NavigateToMainDisposesProperly()
        {
            TestsHelper.StartServicesAndCreateViewModels();
            
            //Setting current sesion to ensure fields are not default
            VaultSession.CurrentSession = TestsHelper.CreateFilledSessionInstance();
            Assert.NotEqual(string.Empty, VaultSession.CurrentSession.VAULTPATH);

            _navigationService.NavigateToMain();

            //Asserting that dispose sets vault path field to default
            Assert.Equal(string.Empty, VaultSession.CurrentSession.VAULTPATH);
        }

        public static TheoryData<ISecureBuffer, Type> InvalidBuffers = new TheoryData<ISecureBuffer, Type>()
        {
            {null!, typeof(ArgumentNullException) },
            {SecureBuffer.Create(0), typeof(ArgumentException) }
        };

        [Theory]
        [MemberData(nameof(InvalidBuffers))]
        internal void NavigateToOpenVaultThrowsForInvalidPassword(ISecureBuffer password, Type expectedException)
        {
            Assert.Throws(expectedException, () => _navigationService.NavigateToOpenVault(password, NormalizedPath.From("TEST")));
        }

        [Theory]
        [MemberData(nameof(TestsHelper.InvalidPaths), MemberType = typeof(TestsHelper))]
        internal void NavigateToOpenVaultThrowsForInvalidVaultPath(NormalizedPath vaultPath, Type expectedException)
        {
            using (ISecureBuffer _ = SecureBuffer.Create(1))
            {
                Assert.Throws(expectedException, () => _navigationService.NavigateToOpenVault(_, vaultPath));
            }
        }

        [Theory]
        [MemberData(nameof(TestsHelper.InvalidPaths), MemberType = typeof(TestsHelper))]
        internal void NavigateToPasswordInputThrowsForInvalidValues(NormalizedPath vaultPath, Type expectedException)
        {
            Assert.Throws(expectedException, () => _navigationService.NavigateToPasswordInput(vaultPath));
        }

        [Theory]
        [MemberData(nameof(TestsHelper.InvalidPaths), MemberType = typeof(TestsHelper))]
        internal void NavigateToEncryptFileThrowsForInvalidValues(NormalizedPath filePath, Type expectedException)
        {
            Assert.Throws(expectedException, () => _navigationService.NavigateToEncryptFile(filePath));
        }

        [Fact]
        internal void NavigateToProgressThrowsForInvalidValues()
        {
            Assert.Throws<ArgumentNullException>(() => _navigationService.NavigateToProgress(null!));
        }

        [Fact]
        internal void NavigateToExceptionThrownThrowsForInvalidValues()
        {
            Assert.Throws<ArgumentNullException>(() => _navigationService.NavigateToExceptionThrown(null!));
        }
    }
}
