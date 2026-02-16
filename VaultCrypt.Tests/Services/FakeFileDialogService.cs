using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Services;

namespace VaultCrypt.Tests.Services
{
    internal class FakeFileDialogService : IFileDialogService
    {
        public string? ReturnValue { get; set; }

        public string? OpenFile(string title, bool allFiles) => ReturnValue;

        public string? OpenFolder(string title) => ReturnValue;

        public string? SaveFile(string fileName) => ReturnValue;
    }
}
