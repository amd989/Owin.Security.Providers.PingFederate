// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

namespace Owin.Security.Providers.PingFederate.Provider
{
    using System.Security.Claims;

    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Provider;

    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class PingFederateAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="PingFederateAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">PingFederate Access token</param>
        /// <param name="identityToken"></param>
        /// <param name="refreshToken"></param>
        public PingFederateAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string identityToken, string refreshToken)
            : base(context)
        {
            this.User = user;
            this.AccessToken = accessToken;
            this.IdentityToken = identityToken;
            this.RefreshToken = refreshToken;

            this.Id = TryGetValue(user, "sub");
            this.Name = TryGetValue(user, "name");
            this.Link = TryGetValue(user, "website");
            this.UserName = TryGetValue(user, "preferred_username");
            this.Email = TryGetValue(user, "email");
        }

        /// <summary>
        /// The Refresh Token
        /// </summary>
        public string RefreshToken { get; set; }

        /// <summary>
        /// The Identity Token
        /// </summary>
        public string IdentityToken { get; set; }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the PingFederate user obtained from the User Info endpoint. it can be overridden in the options
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the PingFederate access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the PingFederate user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string Name { get; private set; }

        public string Link { get; private set; }

        /// <summary>
        /// Gets the PingFederate username
        /// </summary>
        public string UserName { get; private set; }

        /// <summary>
        /// Gets the PingFederate email
        /// </summary>
        public string Email { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JObject user, string propertyName)
        {
            if (user == null) return null;
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
    }
}
