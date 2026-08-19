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

        public Task<string?> OpenFile(string title, bool allFiles) => Task.FromResult(ReturnValue);

        public Task<string?> OpenFolder(string title) => Task.FromResult(ReturnValue);

        public Task<string?> SaveFile(string fileName) => Task.FromResult(ReturnValue);
    }
}
