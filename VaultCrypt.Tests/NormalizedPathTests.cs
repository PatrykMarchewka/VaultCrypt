using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Tests
{
    public class NormalizedPathTests
    {

        string test = new string('a', 100);

        [Fact]
        void NormalizedPathThrowsOnNull()
        {
            Assert.Throws<ArgumentNullException>(() => NormalizedPath.From(null!));
        }

        [Fact]  
        void NormalizedPathDoesNotChangeShortPaths()
        {
            var path = NormalizedPath.From(test);

            Assert.Equal(test, path);
        }

        [Fact]
        void NormalizedPathChangesLongPaths()
        {
            string test = new string('a', 300);
            var path = NormalizedPath.From(test);

            Assert.Equal(@"\\?\" + test, path);
        }

        [Theory]
        [InlineData(@"\\?\" + "aaa")]
        [InlineData(@"\\?\" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
        void NormalizedPathDoesNotAppendAlreadyAppendedPath(string appendedString)
        {
            var path = NormalizedPath.From(appendedString);

            Assert.Equal(appendedString, path);
        }

        [Fact]
        void NormalizedPathReturnsValueOnToString()
        {
            var path = NormalizedPath.From(test);

            Assert.Equal(test, path.ToString());
        }

        [Fact]
        void NormalizedPathConvertsToString()
        {
            var path = NormalizedPath.From(test);

            string pathAsString = path;

            Assert.Equal(test, pathAsString);
        }

        [Fact]
        void NormalizedPathThrowsOnNullValue()
        {
            NormalizedPath path = null!;

            Assert.Throws<ArgumentNullException>(() => { string pathAsString = path; });
        }
    }
}
