// --------------------------------------------------------------------------------------------------------------------
// <copyright file="PingFederateAuthenticationHandlerFactory.cs" company="ShiftMe, Inc.">
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
    using System.Net.Http;

    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security.Infrastructure;

    /// <summary>The ping federate authentication handler factory.</summary>
    public class PingFederateAuthenticationHandlerFactory : IPingFederateAuthenticationHandlerFactory
    {
        #region Fields

        /// <summary>The http client.</summary>
        private readonly HttpClient httpClient;

        /// <summary>The logger.</summary>
        private readonly ILogger logger;

        #endregion

        #region Constructors and Destructors

        /// <summary>Initializes a new instance of the <see cref="PingFederateAuthenticationHandlerFactory"/> class. Initializes a new instance of the <see cref="T:System.Object"/> class.</summary>
        /// <param name="httpClient">The http Client.</param>
        /// <param name="logger">The logger.</param>
        public PingFederateAuthenticationHandlerFactory(HttpClient httpClient, ILogger logger)
        {
            this.httpClient = httpClient;
            this.logger = logger;
        }

        #endregion

        #region Public Methods and Operators

        /// <summary>The create handler.</summary>
        /// <returns>The <see cref="AuthenticationHandler" />.</returns>
        public AuthenticationHandler<PingFederateAuthenticationOptions> CreateHandler()
        {
            return new PingFederateAuthenticationHandler(this.httpClient, this.logger);
        }

        #endregion
    }
}