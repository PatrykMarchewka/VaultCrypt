using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.Tests
{
    public class EncryptedFileInfoTests
    {
        [Fact]
        void InitializedEmpty()
        {
            var empty = new EncryptedFileInfo(null, 0, null);
            Assert.Equal("Unknown file (Corrupted data!)", empty.FileName);
            Assert.Equal("0B", empty.FileSize);
            Assert.Equal("Unknown", empty.EncryptionAlgorithm);
        }

        [Fact]
        void InitializeFull()
        {
            var full = new EncryptedFileInfo("test", 1, EncryptionAlgorithm.GetEncryptionAlgorithmInfo[0]);
            Assert.Equal("test", full.FileName);
            Assert.Equal("1B", full.FileSize);
            Assert.Equal(EncryptionAlgorithm.GetEncryptionAlgorithmInfo[0].Name, full.EncryptionAlgorithm);
        }

        [Theory]
        [InlineData(0, "0B")]
        [InlineData(1, "1B")]
        [InlineData(1_023, "1023B")]
        void FormatSizeFormatsCorrectly_Bytes(ulong size, string expected)
        {
            var result = new EncryptedFileInfo(null, size, null);
            Assert.Equal(expected, result.FileSize);
        }

        [Theory]
        [InlineData(1_024, "1KB")]
        [InlineData(1_536, "1,5KB")]
        [InlineData(1_588, "1,55KB")]
        [InlineData(1_048_575, "1023,99KB")]
        void FormatSizeFormatsCorrectly_Kilobytes(ulong size, string expected)
        {
            var result = new EncryptedFileInfo(null, size, null);
            Assert.Equal(expected, result.FileSize);
        }

        [Theory]
        [InlineData(1_048_576, "1MB")]
        [InlineData(1_572_864, "1,5MB")]
        [InlineData(1_625_293, "1,55MB")]
        [InlineData(1_073_741_823, "1023,99MB")]
        void FormatSizeFormatsCorrectly_Megabytes(ulong size, string expected)
        {
            var result = new EncryptedFileInfo(null, size, null);
            Assert.Equal(expected, result.FileSize);
        }

        [Theory]
        [InlineData(1_073_741_824, "1GB")]
        [InlineData(1_610_612_736, "1,5GB")]
        [InlineData(1_664_299_828, "1,55GB")]
        [InlineData(1_099_511_627_775, "1023,99GB")] 
        void FormatSizeFormatsCorrectly_Gigabytes(ulong size, string expected)
        {
            var result = new EncryptedFileInfo(null, size, null);
            Assert.Equal(expected, result.FileSize);
        }

        [Theory]
        [InlineData(1_099_511_627_776, "1TB")]
        [InlineData(1_649_267_441_664, "1,5TB")]
        [InlineData(1_704_243_023_053, "1,55TB")]
        [InlineData(1_125_899_906_842_623, "1023,99TB")]
        void FormatSizeFormatsCorrectly_Terabytes(ulong size, string expected)
        {
            var result = new EncryptedFileInfo(null, size, null);
            Assert.Equal(expected, result.FileSize);
        }

        [Theory]
        [InlineData(1_125_899_906_842_624, "1PB")]
        [InlineData(1_688_849_860_263_936, "1,5PB")]
        [InlineData(1_745_144_855_606_272, "1,55PB")]
        [InlineData(1_152_921_504_606_846_975, "1023,99PB")]
        void FormatSizeFormatsCorrectly_Petabytes(ulong size, string expected)
        {
            var result = new EncryptedFileInfo(null, size, null);
            Assert.Equal(expected, result.FileSize);
        }

        [Theory]
        [InlineData(1_152_921_504_606_846_976, "1EB")]
        [InlineData(1_729_382_256_910_270_464, "1,5EB")]
        [InlineData(1_787_028_332_140_822_528, "1,55EB")]
        [InlineData(ulong.MaxValue - 1, "15,99EB")]
        [InlineData(ulong.MaxValue, "15,99EB")]
        void FormatSizeFormatsCorrectly_Exabytes(ulong size, string expected)
        {
            var result = new EncryptedFileInfo(null, size, null);
            Assert.Equal(expected, result.FileSize);
        }


    }
}
