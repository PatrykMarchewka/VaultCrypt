using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using VaultCrypt.Avalonia.Services;
using VaultCrypt.ViewModels;

namespace VaultCrypt.Avalonia;

public partial class App : Application
{

    private void OnExit(object? sender, ControlledApplicationLifetimeExitEventArgs e)
    {
        VaultSession.CurrentSession.Dispose();
    }
    
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            //On startup
            ViewModelState.OnStartup(desktop.Args, new DialogService(), new FileDialogService());
            desktop.Exit += OnExit;
            desktop.MainWindow = new MainWindow
            {
                DataContext = ViewModelState.MainWindow
            };
        }

        base.OnFrameworkInitializationCompleted();
    }
}