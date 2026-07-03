using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VaultCrypt.Exceptions;

namespace VaultCrypt.Services
{
    internal interface IExceptionHandler
    {
        /// <summary>
        /// Handles navigation globally after exception gets thrown
        /// </summary>
        /// <param name="ex">Original thrown exception</param>
        public void HandleException(Exception ex);
    }

    internal class ExceptionHandlerService(IDialogService dialogService, INavigationService navigationService) : IExceptionHandler
    {
        private readonly IDialogService dialogService = dialogService;
        private readonly INavigationService navigationService = navigationService;

        public void HandleException(Exception ex)
        {
            switch (ex)
            {
                case VaultUIException uiEx:
                    dialogService.ShowErrorWindow(uiEx);
                    break;
                case VaultException vEx:
                    navigationService.NavigateToExceptionThrown(vEx);
                    break;
                case OperationCanceledException ocEx:
                    navigationService.NavigateToExceptionThrown(new VaultOperationException(VaultException.ErrorReason.OperationCancelled));
                        break;
                default:
                    navigationService.NavigateToExceptionThrown(new VaultOperationException(VaultException.ErrorReason.Other, ex));
                    break;
            }
        }
    }
}
