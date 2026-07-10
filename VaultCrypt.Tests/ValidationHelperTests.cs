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
        internal void NotEmptyStringUsesFallbackValue()
        {
            try
            {
                ValidationHelper.NotEmptyString(null, "");
            }
            catch (Exception ex)
            {
                Assert.Contains("[Unknown field]", ex.Message);
            }
        }

        [Fact]
        internal void NotEmptySecureBufferDoesNotThrowForValidInput()
        {
            var input = SecureBuffer.Create(1);
            ValidationHelper.NotEmptySecureBuffer(input, "");
        }

        [Fact]
        internal void NotEmptySecureBufferThrowsForInvalidInput()
        {
            Assert.Throws<VaultCrypt.Exceptions.VaultUIException>(() => ValidationHelper.NotEmptySecureBuffer(null, ""));
        }

        [Fact]
        internal void NotEmptySecureBufferUsesFallbackValue()
        {
            try
            {
                ValidationHelper.NotEmptySecureBuffer(null, "");
            }
            catch (Exception ex)
            {
                Assert.Contains("[Unknown field]", ex.Message);
            }
        }
    }
}
