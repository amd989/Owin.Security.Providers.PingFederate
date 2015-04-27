// --------------------------------------------------------------------------------------------------------------------
// <copyright file="PingFederateAuthenticationExtensions.cs" company="ShiftMe, Inc.">
//   Copyright © 2015 ShiftMe, Inc.  All rights reserved.
// </copyright>
// <author>Alejandro Mora</author>
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

            var joined = string.Join(
                "&", 
                parameters.Where(pair => !string.IsNullOrEmpty(pair.Value))
                    .Select(pair => string.Format(CultureInfo.InvariantCulture, "{0}={1}", pair.Key, pair.Value)));
            return string.Format(CultureInfo.InvariantCulture, "?{0}", joined);
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