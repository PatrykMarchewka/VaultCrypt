using System.Configuration;
using System.Data;
using System.Windows;

namespace VaultCrypt
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {

        protected override void OnExit(ExitEventArgs args)
        {
            VaultSession.Dispose();
            base.OnExit(args);
        }
    }

}
