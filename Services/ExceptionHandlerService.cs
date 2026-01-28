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
        void HandleException(Exception ex);
    }

    internal class ExceptionHandlerService : IExceptionHandler
    {
        private readonly IDialogService dialogService;
        private readonly INavigationService navigationService;
        public ExceptionHandlerService(IDialogService dialogService, INavigationService navigationService)
        {
            this.dialogService = dialogService;
            this.navigationService = navigationService;
        }

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
                    navigationService.NavigateToExceptionThrown(VaultException.OperationCancelledException(ocEx));
                    break;
                default:
                    navigationService.NavigateToExceptionThrown(ex);
                    break;
            }
        }
    }
}
