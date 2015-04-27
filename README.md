# Owin.Security.Providers.PingFederate

The PingFederate OWIN Middleware OpenIdConnect Client allows your C# Web Application to take advantage of OWIN to start authentication with Ping Federate using the OpenId Connect Authentication module they provide.

## Usage:

All you need to do is add a reference to the packagee using Nuget and add the following to your **Startup.Auth.cs** class 

    public partial class Startup
      {
          public void ConfigureAuth(IAppBuilder app)
          {
              // Enable the application to use a cookie to store information for the signed in user
              app.UseCookieAuthentication(new CookieAuthenticationOptions
              {
                  AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                  LoginPath = new PathString("/Account/Login")
              });
  
              // Use a cookie to temporarily store information about a user logging in with a third party login provider
              app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);
  
              // Uncomment the following lines to enable logging in with third party login providers
              app.UsePingFederateAuthentication(new PingFederateAuthenticationOptions()
              {
                  ClientId = "id",
                  ClientSecret = "super_secret",
                  PingFederateUrl = "https://your-ping-federate-server.com",
                  SignInAsAuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                  AuthenticationType = "PingFederate",
              });
          }
      }
      


