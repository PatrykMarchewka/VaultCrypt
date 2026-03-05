using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Tests
{
    public class ValidationHelperTests
    {
        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData(" ")]
        void NotEmptyStringThrowsForNullOrWhitespace(string input)
        {
            Assert.Throws<VaultCrypt.Exceptions.VaultUIException>(() => ValidationHelper.NotEmptyString(input, ""));
        }

        [Fact]
        void NotEmptyStringDoesNotThrowForValidInput()
        {
            ValidationHelper.NotEmptyString("input", "");
        }
        [Fact]
        void NotEmptySecureStringThrowsForNull()
        {
            Assert.Throws<VaultCrypt.Exceptions.VaultUIException>(() => ValidationHelper.NotEmptySecureString(null, ""));
        }
        [Fact]
        void NotEmptySecureStringThrowsForEmpty()
        {
            Assert.Throws<VaultCrypt.Exceptions.VaultUIException>(() => ValidationHelper.NotEmptySecureString(new SecureString(), ""));
        }

        [Fact]
        void NotEmptySecureStringDoesNotThrowForValidInput()
        {
            SecureString input = new SecureString();
            input.AppendChar('a');

            ValidationHelper.NotEmptySecureString(input, "");
        }
    }
}
