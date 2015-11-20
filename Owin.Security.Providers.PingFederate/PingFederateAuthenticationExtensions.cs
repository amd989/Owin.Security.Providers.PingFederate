// --------------------------------------------------------------------------------------------------------------------
// <copyright file="PingFederateAuthenticationExtensions.cs" company="ShiftMe, Inc.">
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
    using System.Collections.Generic;
    using System.Globalization;
    using System.Linq;

    /// <summary>The ping federate authentication extensions.</summary>
    public static class PingFederateAuthenticationExtensions
    {
        #region Public Methods and Operators

        /// <summary>The to query string.</summary>
        /// <param name="parameters">The parameters.</param>
        /// <returns>The <see cref="string"/>.</returns>
        /// <exception cref="ArgumentNullException">If the parameters are null</exception>
        public static string ToQueryString(this Dictionary<string, string> parameters)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException("parameters");
            }
            
            // Avoiding URL encoding the query string parameters as it is NOT compatible with Ping Federate.
            var query = string.Join("&", parameters.Where(pair => !string.IsNullOrEmpty(pair.Value)).Select(item => string.Format(CultureInfo.InvariantCulture, "{0}={1}", item.Key, item.Value)).ToArray());
            return string.IsNullOrEmpty(query) ? string.Empty : "?" + query;
        }

        /// <summary>The use ping federate authentication.</summary>
        /// <param name="app">The app.</param>
        /// <param name="options">The options.</param>
        /// <returns>The <see cref="IAppBuilder"/>.</returns>
        /// <exception cref="ArgumentNullException">If the parameters are null</exception>
        public static IAppBuilder UsePingFederateAuthentication(
            this IAppBuilder app, 
            PingFederateAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }

            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(PingFederateAuthenticationMiddleware), app, options);

            return app;
        }

        /// <summary>The use ping federate authentication.</summary>
        /// <param name="app">The app.</param>
        /// <param name="clientId">The client id.</param>
        /// <param name="clientSecret">The client secret.</param>
        /// <param name="pingFederateUrl">The ping federate url.</param>
        /// <returns>The <see cref="IAppBuilder"/>.</returns>
        public static IAppBuilder UsePingFederateAuthentication(
            this IAppBuilder app, 
            string clientId, 
            string clientSecret, 
            string pingFederateUrl)
        {
            return
                app.UsePingFederateAuthentication(
                    new PingFederateAuthenticationOptions
                        {
                            ClientId = clientId, 
                            ClientSecret = clientSecret, 
                            PingFederateUrl = pingFederateUrl
                        });
        }

        #endregion
    }
}