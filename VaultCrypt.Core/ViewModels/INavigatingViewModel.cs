using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.ViewModels
{
    /// <summary>
    /// Represents viewmodel that can navigate to other viewmodels
    /// </summary>
    public interface INavigatingViewModel : IViewModel
    {
        /// <summary>
        /// Event used to request navigation to another viewmodel
        /// </summary>
        public event Action<NavigationRequest> NavigationRequested;
    }
}
