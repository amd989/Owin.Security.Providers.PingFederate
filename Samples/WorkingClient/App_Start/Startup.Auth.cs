// --------------------------------------------------------------------------------------------------------------------
// <copyright file="Startup.Auth.cs" company="">
//   
// </copyright>
// <summary>
//   The startup.
// </summary>
// --------------------------------------------------------------------------------------------------------------------
namespace OwinOpenIdMiddleware
{
    using System;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using System.Web.Helpers;

    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Cookies;

    using Owin;
    using Owin.Security.Providers.PingFederate;
    using Owin.Security.Providers.PingFederate.Provider;

    /// <summary>The startup.</summary>
    public partial class Startup
    {
        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        #region Public Methods and Operators

        /// <summary>The configure authentication.</summary>
        /// <param name="app">The app.</param>
        public void ConfigureAuth(IAppBuilder app)
        {
            AntiForgeryConfig.UniqueClaimTypeIdentifier = "antiforgery";
            const string Cookies = "PingFederateCookie";
            app.SetDefaultSignInAsAuthenticationType(Cookies);
            const int SessionTimeout = 15;
            app.UseCookieAuthentication(
                new CookieAuthenticationOptions
                    {
                        LoginPath = new PathString("/"), 
                        AuthenticationMode = AuthenticationMode.Active, 
                        AuthenticationType = Cookies, 
                        ExpireTimeSpan = TimeSpan.FromMinutes(SessionTimeout), 
                        CookieSecure = CookieSecureOption.SameAsRequest, 
                        CookiePath = "/", 
                        SlidingExpiration = true
                    });

            // SET UP VARIABLES
            const string ClientId = "";
            const string ClientSecret = "";
            const string Scopes = "openid";
            const string PingServer = "";
            const string IdpAdapterId = "";

            app.UsePingFederateAuthentication(
                new PingFederateAuthenticationOptions
                    {
                        ClientId = ClientId, 
                        ClientSecret = ClientSecret, 
                        RequestUserInfo = false, 
                        AuthenticationMode = AuthenticationMode.Active, 
                        Scope = Scopes.Split(' '), 
                        PingFederateUrl = PingServer, 
                        IdpAdapterId = IdpAdapterId, 
                        DiscoverMetadata = true,
                        Endpoints =
                            new PingFederateAuthenticationOptions.PingFederateAuthenticationEndpoints
                                {
                                    MetadataEndpoint = PingFederateAuthenticationOptions.OpenIdConnectMetadataEndpoint
                                }, 
                        SignInAsAuthenticationType = Cookies, 
                        Provider = new PingFederateAuthenticationProvider
                                       {
                                          OnAuthenticated = context =>
                                               {
                                                   context.Identity.AddClaim(new Claim("antiforgery", Guid.NewGuid().ToString()));

                                                   return Task.FromResult(0);
                                               }
                                       }
                    });
        }

        #endregion
    }
}