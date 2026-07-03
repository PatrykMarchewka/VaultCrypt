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
            ViewModelState.OnStartup(e.Args);

            var window = new MainWindow
            {
                DataContext = ViewModelState.MainWindow
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
