using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Threading;

namespace VaultCrypt
{
    public sealed class RetryHelper
    {
        /// <summary>
        /// Tries to execute <paramref name="tryAction"/> and in case of thrown exception it evaluates <paramref name="shouldRetry"/> to decide whether it should retry the action. <br/>
        /// If <paramref name="shouldRetry"/> is set to <c>null</c> or returns <c>true</c> it executes <paramref name="catchAction"/> after which waits a second before retrying until <paramref name="tryAction"/> succeedes or <paramref name="maxRetries"/> limit is reached. <br/>
        /// </summary>
        /// <typeparam name="T">Type to return</typeparam>
        /// <param name="tryAction">Task to execute</param>
        /// <param name="catchAction">Task to execute each time <paramref name="tryAction"/> throws, runs only if <paramref name="shouldRetry"/> returns <c>true</c></param>
        /// <param name="maxRetries">Maximum number of retries before giving up. Suggested value for visible failures is 100, for others 10</param>
        /// <param name="shouldRetry">Predicate whether <paramref name="catchAction"/> is allowed to run and restart based on exception thrown by <paramref name="tryAction"/></param>
        /// <returns>Return value of <typeparamref name="T"/> from <paramref name="tryAction"/></returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="maxRetries"/> is set to negative or zero value</exception>
        /// <exception cref="VaultCrypt.Exceptions.VaultException">Thrown when <paramref name="tryAction"/> failed and threw <paramref name="maxRetries"/> times</exception>
        /// <exception cref="Exception">Thrown when <paramref name="tryAction"/> threw exception and <paramref name="shouldRetry"/> returned <c>false</c></exception>
        /// <exception cref="UnreachableException">Should never be thrown, indicates error in logic</exception>
        public static async Task<T> TryUntilSuccessAsync<T>(Func<Task<T>> tryAction, Func<Task>? catchAction = null, int maxRetries = 100, Func<Exception, bool>? shouldRetry = null)
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxRetries);

            //Task yields to ensure that UI stays responsive
            await Task.Yield();
            for (int attempt = 1; attempt <= maxRetries; attempt++)
            {
                try
                {
                    return await tryAction();
                }
                catch (Exception ex)
                {
                    if (attempt == maxRetries) throw new VaultCrypt.Exceptions.VaultException(Exceptions.VaultException.ErrorContext.VaultSession, Exceptions.VaultException.ErrorReason.MaxRetriesReached, ex);
                    if (shouldRetry is not null && !shouldRetry(ex)) throw;
                    if (catchAction is not null)
                    {
                        await catchAction();
                        await Task.Delay(1000);
                    }
                }
            }
            throw new UnreachableException(); //Should never reach this point
        }

        /// <inheritdoc cref="TryUntilSuccessAsync{T}(Func{Task{T}}, Func{Task}?, int, Func{Exception, bool}?)"/>
        public static async Task<T> TryUntilSuccessAsync<T>(Func<Task<T>> tryAction, Action? catchAction = null, int maxRetries = 100, Func<Exception, bool>? shouldRetry = null)
        {
            return await TryUntilSuccessAsync<T>(tryAction, catchAction: catchAction is null ? null : () => { catchAction(); return Task.CompletedTask; }, maxRetries, shouldRetry);
        }

        /// <inheritdoc cref="TryUntilSuccessAsync{T}(Func{Task{T}}, Func{Task}?, int, Func{Exception, bool}?)"/>
        public static async Task<T> TryUntilSuccessAsync<T>(Func<T> tryAction, Action? catchAction = null, int maxRetries = 100, Func<Exception, bool>? shouldRetry = null)
        {
            return await TryUntilSuccessAsync<T>(() => Task.Run(tryAction), catchAction: catchAction is null ? null : () => { catchAction(); return Task.CompletedTask; }, maxRetries, shouldRetry);
        }

        /// <inheritdoc cref="TryUntilSuccessAsync{T}(Func{Task{T}}, Func{Task}?, int, Func{Exception, bool}?)"/>
        public static async Task TryUntilSuccessAsync(Action tryAction, Action? catchAction = null, int maxRetries = 100, Func<Exception, bool>? shouldRetry = null)
        {
            await TryUntilSuccessAsync(() => { tryAction(); return Task.CompletedTask; }, catchAction, maxRetries, shouldRetry);
        }

        /// <summary>
        /// Synchronous version of <see cref="TryUntilSuccessAsync{T}(Func{Task{T}}, Func{Task}?, int, Func{Exception, bool}?)"/>
        /// </summary>
        /// <typeparam name="T">Type to return</typeparam>
        /// <param name="tryAction">Task to execute</param>
        /// <param name="catchAction">Task to execute each time <paramref name="tryAction"/> throws, runs only if <paramref name="shouldRetry"/> returns <c>true</c></param>
        /// <param name="maxRetries">Maximum number of retries before giving up. Suggested value for visible failures is 100, for others 10</param>
        /// <param name="shouldRetry">Predicate whether <paramref name="catchAction"/> is allowed to run and restart based on exception thrown by <paramref name="tryAction"/></param>
        /// <returns>Return value of <typeparamref name="T"/> from <paramref name="tryAction"/></returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="maxRetries"/> is set to negative or zero value</exception>
        /// <exception cref="VaultCrypt.Exceptions.VaultException">Thrown when <paramref name="tryAction"/> failed and threw <paramref name="maxRetries"/> times</exception>
        /// <exception cref="Exception">Thrown when <paramref name="tryAction"/> threw exception and <paramref name="shouldRetry"/> returned <c>false</c></exception>
        /// <exception cref="UnreachableException">Should never be thrown, indicates error in logic</exception>
        public static T TryUntilSuccess<T>(Func<T> tryAction, Action? catchAction = null, int maxRetries = 100, Func<Exception, bool>? shouldRetry = null)
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxRetries);

            var frame = new DispatcherFrame();
            ExceptionDispatchInfo? exceptionInfo = null;
            T result = default!;
            bool isResultSet = false;

            async void Run()
            {
                try
                {
                    for (int attempt = 1; attempt <= maxRetries; attempt++)
                    {
                        try
                        {
                            result = tryAction();
                            isResultSet = true;
                            return;
                        }
                        catch (Exception ex)
                        {
                            if (attempt == maxRetries)
                            {
                                exceptionInfo = ExceptionDispatchInfo.Capture(new VaultCrypt.Exceptions.VaultException(Exceptions.VaultException.ErrorContext.VaultSession, Exceptions.VaultException.ErrorReason.MaxRetriesReached, ex));
                                return;
                            }
                            if (shouldRetry is not null && !shouldRetry(ex))
                            {
                                exceptionInfo = ExceptionDispatchInfo.Capture(ex);
                                return;
                            }
                            catchAction?.Invoke();
                            await Task.Delay(1000);
                        }
                    }
                }
                finally
                {
                    frame.Continue = false;
                }
            }

            Run();
            Dispatcher.PushFrame(frame);
            exceptionInfo?.Throw();
            if (!isResultSet) throw new UnreachableException();
            return result;
        }

        /// <inheritdoc cref="TryUntilSuccess{T}(Func{T}, Action?, int, Func{Exception, bool}?)"/>
        public static void TryUntilSuccess(Action tryAction, Action? catchAction = null, int maxRetries = 100, Func<Exception, bool>? shouldRetry = null)
        {
            TryUntilSuccess<bool>(tryAction: () => { tryAction(); return true; }, catchAction, maxRetries, shouldRetry);
        }
    }
}
