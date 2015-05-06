[![Build status](https://ci.appveyor.com/api/projects/status/5f7gyucnoq0b8rld/branch/master?svg=true)](https://ci.appveyor.com/project/amd989/owin-security-providers-pingfederate/branch/master)

[![Nuget](https://img.shields.io/nuget/v/Owin.Security.Providers.PingFederate.svg)](https://www.nuget.org/packages/Owin.Security.Providers.PingFederate)
[![Nuget](https://img.shields.io/nuget/dt/Owin.Security.Providers.PingFederate.svg)](https://www.nuget.org/packages/Owin.Security.Providers.PingFederate)

# Owin.Security.Providers.PingFederate

The PingFederate OWIN Middleware OpenIdConnect Client allows your C# Web Application to take advantage of OWIN to start authentication with Ping Federate using the OpenId Connect Authentication module they provide.

Configuration in Ping has to be made to support this client. You need to have the OAuth2 module enabled, configure Clients, configure mappings, poliecies, adapters, etc. Everything is explained in the PingFederate documentation. If you have problems or questions contact me using the Issues tab.

Samples have been added, please refer to them to get an idea on how to set up the Middleware. Also refer to the main project page for an step by step.

## Usage:

All you need to do is add a reference to the package using Nuget and add the following to your **Startup.Auth.cs** class 

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
              
              app.UsePingFederateAuthentication(new PingFederateAuthenticationOptions()
              {
                  ClientId = "id",
                  ClientSecret = "super_secret",
                  PingFederateUrl = "https://your-ping-federate-server.com",
                  SignInAsAuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
              });
          }
      }
      
      

## NuGet

Download the NuGet package [here](http://bit.ly/OpenIDConnect)


