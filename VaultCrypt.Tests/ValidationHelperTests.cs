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
        [Fact]
        internal void NotEmptyStringDoesNotThrowForValidInput()
        {
            ValidationHelper.NotEmptyString("input", "");
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData(" ")]
        internal void NotEmptyStringThrowsInvalidInput(string input)
        {
            Assert.Throws<VaultCrypt.Exceptions.VaultUIException>(() => ValidationHelper.NotEmptyString(input, ""));
        }

        [Fact]
        internal void NotEmptySecureStringDoesNotThrowForValidInput()
        {
            SecureString input = new SecureString();
            input.AppendChar('a');

            ValidationHelper.NotEmptySecureString(input, "");
        }

        public static TheoryData<SecureString> InvalidSecureString = new TheoryData<SecureString> { null!, new SecureString() };
        [Theory]
        [MemberData(nameof(InvalidSecureString))]
        internal void NotEmptySecureStringThrowsForInvalidInput(SecureString input)
        {
            Assert.Throws<VaultCrypt.Exceptions.VaultUIException>(() => ValidationHelper.NotEmptySecureString(input, ""));
        }
    }
}
