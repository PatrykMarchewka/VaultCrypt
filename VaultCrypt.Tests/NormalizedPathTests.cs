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
        internal void NormalizedPathThrowsOnNull()
        {
            Assert.Throws<ArgumentNullException>(() => NormalizedPath.From(null!));
        }

        [Fact]  
        internal void NormalizedPathDoesNotChangeShortPaths()
        {
            var path = NormalizedPath.From(test);

            Assert.Equal(test, path);
        }

        [Fact]
        internal void NormalizedPathChangesLongPaths()
        {
            string test = new string('a', 300);
            var path = NormalizedPath.From(test);

            Assert.Equal(@"\\?\" + test, path);
        }

        [Theory]
        [InlineData(@"\\?\" + "aaa")]
        [InlineData(@"\\?\" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
        internal void NormalizedPathDoesNotAppendAlreadyAppendedPath(string appendedString)
        {
            var path = NormalizedPath.From(appendedString);

            Assert.Equal(appendedString, path);
        }

        [Fact]
        internal void NormalizedPathReturnsValueOnToString()
        {
            var path = NormalizedPath.From(test);

            Assert.Equal(test, path.ToString());
        }

        [Fact]
        internal void NormalizedPathConvertsToString()
        {
            var path = NormalizedPath.From(test);

            string pathAsString = path;

            Assert.Equal(test, pathAsString);
        }

        [Fact]
        internal void NormalizedPathThrowsOnNullValue()
        {
            NormalizedPath path = null!;

            Assert.Throws<ArgumentNullException>(() => { string pathAsString = path; });
        }
    }
}
