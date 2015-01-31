namespace Owin.Security.Providers.PingFederate
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Linq;

    public static class PingFederateAuthenticationExtensions
    {
        public static IAppBuilder UsePingFederateAuthentication(this IAppBuilder app,
            PingFederateAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(PingFederateAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UsePingFederateAuthentication(this IAppBuilder app, string clientId, string clientSecret, string pingFederateUrl)
        {
            return app.UsePingFederateAuthentication(new PingFederateAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret,
                PingFederateUrl = pingFederateUrl
            });
        }

        public static string ToQueryString(this Dictionary<string, string> parameters)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException("parameters");
            }

            var joined = string.Join("&", parameters.Where(pair => !string.IsNullOrEmpty(pair.Value)).Select(pair => string.Format(CultureInfo.InvariantCulture, "{0}={1}", pair.Key, pair.Value)));
            return string.Format(CultureInfo.InvariantCulture, "?{0}", joined);
        }
    }
}