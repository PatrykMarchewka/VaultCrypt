using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.ViewModels
{
    internal interface INavigatingViewModel
    {
        event Action<NavigationRequest> NavigationRequested;
    }
}
