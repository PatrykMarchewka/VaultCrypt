using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using VaultCrypt.ViewModels;

namespace VaultCrypt.Views
{
    /// <summary>
    /// Logika interakcji dla klasy CreateVault.xaml
    /// </summary>
    public partial class CreateVault : UserControl
    {
        public CreateVault()
        {
            InitializeComponent();
        }

        //Code behind because PasswordBox doesnt have proper bindings
        private void PasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            if (DataContext is CreateVaultViewModel vm)
            {
                vm.Password = ((PasswordBox)sender).SecurePassword;
            }
        }
    }
}
