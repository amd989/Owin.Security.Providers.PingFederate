// --------------------------------------------------------------------------------------------------------------------
// <copyright file="IPingFederateAuthenticationProvider.cs" company="ShiftMe, Inc.">
//   Copyright © 2015 ShiftMe, Inc.  All rights reserved.
// </copyright>
// --------------------------------------------------------------------------------------------------------------------

namespace Owin.Security.Providers.PingFederate.Provider
{
    using System.Threading.Tasks;

    /// <summary>
    /// Specifies callback methods which the <see cref="PingFederateAuthenticationMiddleware"></see> invokes to enable developer control over the authentication process. />
    /// </summary>
    public interface IPingFederateAuthenticationProvider
    {
        /// <summary>
        /// Invoked whenever PingFederate successfully authenticates a user
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task Authenticated(PingFederateAuthenticatedContext context);

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task ReturnEndpoint(PingFederateReturnEndpointContext context);

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        /// <param name="context">The context</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task Authenticating(PingFederateAuthenticatingContext context);

        /// <summary>Invoked prior to calling the token request endpoint on PingFederate</summary>
        /// <param name="context">The context</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task TokenRequest(PingFederateTokenRequestContext context);
    }
}