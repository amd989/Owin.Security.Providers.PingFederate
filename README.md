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


## License

This project is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    
See https://www.gnu.org/licenses/gpl-3.0-standalone.html

