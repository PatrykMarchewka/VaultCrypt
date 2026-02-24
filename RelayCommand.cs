using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;

namespace VaultCrypt
{
    public class RelayCommand : ICommand
    {
        private readonly Action<object>? _execute;
        private readonly Func<object, Task>? _asyncExecute;
        private readonly Func<object, bool>? _canExecute;
        private static event Action<Exception> ExceptionThrowRequested = null!;

        public RelayCommand(Action<object> execute, Func<object,bool>? canExecute = null)
        {
            _execute = execute;
            _canExecute = canExecute;
        }

        public RelayCommand(Func<object, Task> execute, Func<object, bool>? canExecute = null)
        {
            _asyncExecute = execute;
            _canExecute = canExecute;
        }

        public static void SubscribeToExceptionThrowEvent(Action<Exception> action) => ExceptionThrowRequested += action;
        public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
        public bool CanExecute(object parameter) { return _canExecute?.Invoke(parameter) ?? true; }
        public async void Execute(object parameter)
        {
            try
            {
                if (_asyncExecute != null) await _asyncExecute(parameter);
                else _execute!(parameter);
            }
            catch (Exception ex)
            {
                ExceptionThrowRequested?.Invoke(ex);
            }
            
        }
        public event EventHandler? CanExecuteChanged;
    }
}
