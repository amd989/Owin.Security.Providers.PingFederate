// --------------------------------------------------------------------------------------------------------------------
// <copyright file="PingFederateAuthenticatedContext.cs" company="ShiftMe, Inc.">
//   Copyright © 2015 ShiftMe, Inc.  All rights reserved.
// </copyright>
// <author>Alejandro Mora</author>
// --------------------------------------------------------------------------------------------------------------------
namespace Owin.Security.Providers.PingFederate.Provider
{
    using System.Security.Claims;

    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Provider;

    using Newtonsoft.Json.Linq;

    /// <summary>
    ///     Contains information about the login session as well as the user
    ///     <see cref="System.Security.Claims.ClaimsIdentity" />.
    /// </summary>
    public class PingFederateAuthenticatedContext : BaseContext
    {
        #region Constructors and Destructors

        /// <summary>Initializes a new instance of the <see cref="PingFederateAuthenticatedContext"/> class. Initializes a <see cref="PingFederateAuthenticatedContext"/></summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">PingFederate Access token</param>
        /// <param name="identityToken">The identity Token.</param>
        /// <param name="refreshToken">The refresh Token.</param>
        public PingFederateAuthenticatedContext(
            IOwinContext context, 
            JObject user, 
            string accessToken, 
            string identityToken, 
            string refreshToken)
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

        #endregion

        #region Public Properties

        /// <summary>
        ///     Gets the PingFederate access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        ///     Gets the PingFederate email
        /// </summary>
        public string Email { get; private set; }

        /// <summary>
        ///     Gets the PingFederate user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        ///     Gets or sets the <see cref="ClaimsIdentity" /> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>Gets or sets the identity token.</summary>
        public string IdentityToken { get; set; }

        /// <summary>Gets the link.</summary>
        public string Link { get; private set; }

        /// <summary>
        ///     Gets the user's name
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        ///     Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        /// <summary>Gets or sets the refresh token.</summary>
        public string RefreshToken { get; set; }

        /// <summary>
        ///     Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        ///     Contains the PingFederate user obtained from the User Info endpoint. it can be overridden in the options
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        ///     Gets the PingFederate username
        /// </summary>
        public string UserName { get; private set; }

        #endregion

        #region Methods

        /// <summary>The try get value.</summary>
        /// <param name="user">The user.</param>
        /// <param name="propertyName">The property name.</param>
        /// <returns>The <see cref="string"/>.</returns>
        private static string TryGetValue(JObject user, string propertyName)
        {
            if (user == null)
            {
                return null;
            }

            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }

        #endregion
    }
}