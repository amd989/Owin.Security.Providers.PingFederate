// --------------------------------------------------------------------------------------------------------------------
// <copyright company="ShiftMe, Inc." file="PingFederateReturnEndpointContext.cs">
//   Copyright © 2015 ShiftMe, Inc.  All rights reserved.
// </copyright>
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
