using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultCrypt.ViewModels
{
    /// <summary>
    /// Represents viewmodel that can be navigated to and/or navigates to other viewmodels
    /// </summary>
    public interface INavigatingViewModel
    {
        /// <summary>
        /// Event used to request navigation to another viewmodel
        /// </summary>
        public event Action<NavigationRequest> NavigationRequested;
    }
}
