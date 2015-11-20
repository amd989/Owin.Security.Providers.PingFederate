// --------------------------------------------------------------------------------------------------------------------
// <copyright file="IPingFederateAuthenticationHandlerFactory.cs" company="ShiftMe, Inc.">
//   This program is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//   GNU General Public License for more details.
// </copyright>
// <author>Alejandro Mora</author>
// <summary>
//   
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace Owin.Security.Providers.PingFederate.Provider
{
    using Microsoft.Owin.Security.Infrastructure;

    /// <summary>The PingFederateHandlerFactory interface.</summary>
    public interface IPingFederateAuthenticationHandlerFactory
    {
        #region Public Methods and Operators

        /// <summary>The create handler.</summary>
        /// <returns>The <see cref="AuthenticationHandler"/>.</returns>
        AuthenticationHandler<PingFederateAuthenticationOptions> CreateHandler();

        #endregion
    }
}