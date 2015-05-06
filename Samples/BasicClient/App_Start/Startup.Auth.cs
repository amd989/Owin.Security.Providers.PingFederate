using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Owin;

namespace BasicClient
{
    using Microsoft.AspNet.Identity;
    using Microsoft.Owin.Security;

    using Owin.Security.Providers.PingFederate;

    public partial class Startup
    {
        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            const string SignInAsAuthenticationType = "PingFederate";
            app.SetDefaultSignInAsAuthenticationType(SignInAsAuthenticationType);

            // Enable the application to use a cookie to store information for the signed in user
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = SignInAsAuthenticationType,
                LoginPath = new PathString("/Account/Login")
            });

            // Use a cookie to temporarily store information about a user logging in with a third party login provider
            // app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            const string PingServerUrl = "https://your-ping-federate-server.com";
            app.UsePingFederateAuthentication(new PingFederateAuthenticationOptions()
            {
                ClientId = "id",
                ClientSecret = "super_secret",
                PingFederateUrl = PingServerUrl,
                ////DiscoverMetadata = false, // Set to false to avoid discovering metatada, you need to set the Endpoints manually. (shown below)
                SignInAsAuthenticationType = SignInAsAuthenticationType,
                // if DiscoveryMetadata = false then uncomment this                                 
                ////Endpoints = new PingFederateAuthenticationOptions.PingFederateAuthenticationEndpoints()
                ////                {
                ////                    AuthorizationEndpoint = PingServerUrl + PingFederateAuthenticationOptions.AuthorizationEndpoint,
                ////                    TokenEndpoint = PingServerUrl + PingFederateAuthenticationOptions.TokenEndpoint,
                ////                    UserInfoEndpoint = PingServerUrl + PingFederateAuthenticationOptions.UserInfoEndpoint
                ////                }
                
            });
        }
    }
}