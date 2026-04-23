using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt
{
    public sealed class RetryHelper
    {
        public static async Task<T> TryUntilSuccess<T>(Func<Task<T>> tryAction, Func<Task>? catchAction = null, int maxRetries = 100)
        {
            for (int attempt = 1; attempt <= maxRetries; attempt++)
            {
                try
                {
                    return await tryAction();
                }
                catch (Exception ex)
                {
                    if (attempt == maxRetries) throw new VaultCrypt.Exceptions.VaultException(Exceptions.VaultException.ErrorContext.VaultSession, Exceptions.VaultException.ErrorReason.MaxRetriesReached, ex);
                    if(catchAction is not null) await catchAction();
                    await Task.Delay(1000);
                }
            }
            throw new UnreachableException(); //Should never reach this point
        }

        public static async Task<T> TryUntilSuccess<T>(Func<Task<T>> tryAction, Action? catchAction = null, int maxRetries = 100)
        {
            return await TryUntilSuccess<T>(tryAction, catchAction: catchAction is null ? null : () => { catchAction(); return Task.CompletedTask; }, maxRetries);
        }

        public static void TryUntilSuccess(Action tryAction, Action? catchAction = null, int maxRetries = 100)
        {
            TryUntilSuccess<bool>(
                tryAction: () => { tryAction(); return Task.FromResult(true); },
                catchAction: catchAction is null ? null : () => { catchAction(); return Task.CompletedTask; },
                maxRetries
                ).GetAwaiter().GetResult();
        }
    }
}
