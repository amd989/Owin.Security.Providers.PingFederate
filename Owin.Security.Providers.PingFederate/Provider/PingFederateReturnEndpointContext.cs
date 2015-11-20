// --------------------------------------------------------------------------------------------------------------------
// <copyright company="ShiftMe, Inc." file="PingFederateReturnEndpointContext.cs">
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
    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Provider;

    /// <summary>
    /// Provides context information to middleware providers.
    /// </summary>
    public class PingFederateReturnEndpointContext : ReturnEndpointContext
    {
        /// <summary>Initializes a new instance of the <see cref="PingFederateReturnEndpointContext"/> class. 
        /// </summary>
        /// <param name="context">OWIN environment</param>
        /// <param name="ticket">The authentication ticket</param>
        public PingFederateReturnEndpointContext(
            IOwinContext context,
            AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }
    }
}
