// --------------------------------------------------------------------------------------------------------------------
// <copyright file="PingFederateAuthenticationMiddleware.cs" company="ShiftMe, Inc.">
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

namespace Owin.Security.Providers.PingFederate
{
    using System;
    using System.Globalization;
    using System.Net.Http;

    using Microsoft.Owin;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.DataHandler;
    using Microsoft.Owin.Security.DataProtection;
    using Microsoft.Owin.Security.Infrastructure;

    using Owin.Security.Providers.PingFederate.Properties;
    using Owin.Security.Providers.PingFederate.Provider;

    /// <summary>The ping federate authentication middleware.</summary>
    public class PingFederateAuthenticationMiddleware : AuthenticationMiddleware<PingFederateAuthenticationOptions>
    {
        #region Fields

        /// <summary>The http client.</summary>
        private readonly HttpClient httpClient;

        /// <summary>The logger.</summary>
        private readonly ILogger logger;

        #endregion

        #region Constructors and Destructors

        /// <summary>Initializes a new instance of the <see cref="PingFederateAuthenticationMiddleware"/> class.</summary>
        /// <param name="next">The next.</param>
        /// <param name="app">The app.</param>
        /// <param name="options">The options.</param>
        /// <exception cref="ArgumentException">If any of the required parameters is empty</exception>
        public PingFederateAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, PingFederateAuthenticationOptions options)
            : base(next, options)
        {
            if (string.IsNullOrWhiteSpace(this.Options.ClientId))
            {
                throw new ArgumentException(
                    string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "ClientId"));
            }

            if (string.IsNullOrWhiteSpace(this.Options.ClientSecret))
            {
                throw new ArgumentException(
                    string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "ClientSecret"));
            }

            if (string.IsNullOrWhiteSpace(this.Options.PingFederateUrl))
            {
                throw new ArgumentException(
                    string.Format(
                        CultureInfo.CurrentCulture, 
                        Resources.Exception_OptionMustBeProvided, 
                        "PingFederateUrl"));
            }

            this.logger = app.CreateLogger<PingFederateAuthenticationMiddleware>();

            if (this.Options.Provider == null)
            {
                this.Options.Provider = new PingFederateAuthenticationProvider();
            }

            if (this.Options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(
                    typeof(PingFederateAuthenticationMiddleware).FullName, 
                    this.Options.AuthenticationType, 
                    "v1");
                this.Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            if (string.IsNullOrEmpty(this.Options.SignInAsAuthenticationType))
            {
                this.Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }

            this.httpClient = new HttpClient(ResolveHttpMessageHandler(this.Options))
                                  {
                                      Timeout = this.Options.BackchannelTimeout, MaxResponseContentBufferSize = 1024 * 1024 * 10, 
                                  };

            if (this.Options.AuthenticationHandlerFactory == null)
            {
                this.Options.AuthenticationHandlerFactory = new PingFederateAuthenticationHandlerFactory(this.httpClient, this.logger);
            }

            this.httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Microsoft Owin PingFederate middleware");
            this.httpClient.DefaultRequestHeaders.ExpectContinue = false;
        }

        #endregion

        #region Methods

        /// <summary>
        ///     Provides the <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> object for processing
        ///     authentication-related requests.
        /// </summary>
        /// <returns>
        ///     An <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> configured with the
        ///     <see cref="T:Owin.Security.Providers.PingFederate.PingFederateAuthenticationOptions" /> supplied to the
        ///     constructor.
        /// </returns>
        protected override AuthenticationHandler<PingFederateAuthenticationOptions> CreateHandler()
        {
            return this.Options.AuthenticationHandlerFactory.CreateHandler();
        }

        /// <summary>The resolve http message handler.</summary>
        /// <param name="options">The options.</param>
        /// <returns>The <see cref="HttpMessageHandler"/>.</returns>
        /// <exception cref="InvalidOperationException">If the web request handler is null</exception>
        private static HttpMessageHandler ResolveHttpMessageHandler(PingFederateAuthenticationOptions options)
        {
            var handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            // If they provided a validator, apply it or fail.
            if (options.BackchannelCertificateValidator != null)
            {
                // Set the cert validate callback
                var webRequestHandler = handler as WebRequestHandler;
                if (webRequestHandler == null)
                {
                    throw new InvalidOperationException(Resources.Exception_ValidatorHandlerMismatch);
                }

                webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
            }

            return handler;
        }

        #endregion
    }
}