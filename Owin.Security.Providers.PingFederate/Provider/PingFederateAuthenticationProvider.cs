// --------------------------------------------------------------------------------------------------------------------
// <copyright file="PingFederateAuthenticationProvider.cs" company="ShiftMe, Inc.">
//   Copyright © 2015 ShiftMe, Inc.  All rights reserved.
// </copyright>
// <summary>
//   Default <see cref="IPingFederateAuthenticationProvider" /> implementation.
// </summary>
// --------------------------------------------------------------------------------------------------------------------
namespace Owin.Security.Providers.PingFederate.Provider
{
    using System;
    using System.Threading.Tasks;

    /// <summary>
    /// Default <see cref="IPingFederateAuthenticationProvider"/> implementation.
    /// </summary>
    public class PingFederateAuthenticationProvider : IPingFederateAuthenticationProvider
    {
        #region Constructors and Destructors

        /// <summary>Initializes a new instance of the <see cref="PingFederateAuthenticationProvider"/> class. 
        /// Initializes a <see cref="PingFederateAuthenticationProvider"/></summary>
        public PingFederateAuthenticationProvider()
        {
            this.OnAuthenticated = context => Task.FromResult<object>(null);
            this.OnReturnEndpoint = context => Task.FromResult<object>(null);
            this.OnAuthenticating = context => Task.FromResult<object>(null);
            this.OnTokenRequest = context => Task.FromResult<object>(null);
        }

        #endregion

        #region Public Properties

        /// <summary>
        /// Gets or sets the function that is invoked when the Authenticated method is invoked.
        /// </summary>
        public Func<PingFederateAuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        /// Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.
        /// </summary>
        public Func<PingFederateAuthenticatingContext, Task> OnAuthenticating { get; set; }

        /// <summary>
        /// Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.
        /// </summary>
        public Func<PingFederateReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        /// <summary>Gets or sets the on token request.</summary>
        public Func<PingFederateTokenRequestContext, Task> OnTokenRequest { get; set; }

        #endregion

        #region Public Methods and Operators

        /// <summary>Invoked whenever PingFederate successfully authenticates a user</summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task Authenticated(PingFederateAuthenticatedContext context)
        {
            return this.OnAuthenticated(context);
        }

        /// <summary>Invoked prior to calling the authorization endpoint in PingFederate</summary>
        /// <param name="context">The context</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task Authenticating(PingFederateAuthenticatingContext context)
        {
            return this.OnAuthenticating(context);
        }

        /// <summary>Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.</summary>
        /// <param name="context">The context</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task ReturnEndpoint(PingFederateReturnEndpointContext context)
        {
            return this.OnReturnEndpoint(context);
        }

        /// <summary>Invoked prior to calling the token request endpoint on PingFederate</summary>
        /// <param name="context">The context</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task TokenRequest(PingFederateTokenRequestContext context)
        {
            return this.OnTokenRequest(context);
        }

        #endregion
    }
}