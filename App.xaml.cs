using System.Configuration;
using System.Data;
using System.Windows;
using VaultCrypt.ViewModels;
using VaultCrypt.Services;

namespace VaultCrypt
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {


        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            ViewModelState vms = new ViewModelState();
            var navigationService = new NavigationService(vms);
            var dialogService = new DialogService();
            var exceptionService = new ExceptionHandlerService(dialogService, navigationService);
            RelayCommand.SubscribeToExceptionThrowEvent((ex) => exceptionService.HandleException(ex));
            navigationService.ChangeView += viewmodel => vms.MainWindow.CurrentView = viewmodel;
            if (e.Args.Length > 0) navigationService.NavigateToPasswordInput(NormalizedPath.From(e.Args[0]));
            else navigationService.NavigateToMain();
            var window = new MainWindow
            {
                DataContext = vms.MainWindow
            };
            window.Show();
        }

        protected override void OnExit(ExitEventArgs args)
        {
            VaultSession.CurrentSession.Dispose();
            base.OnExit(args);
        }
    }

}
