// --------------------------------------------------------------------------------------------------------------------
// <copyright file="IPingFederateAuthenticationHandlerFactory.cs" company="ShiftMe, Inc.">
//   Copyright © 2015 ShiftMe, Inc.  All rights reserved.
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