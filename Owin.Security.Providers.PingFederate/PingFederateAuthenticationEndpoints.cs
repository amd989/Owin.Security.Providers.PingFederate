// --------------------------------------------------------------------------------------------------------------------
// <copyright file="PingFederateAuthenticationEndpoints.cs" company="ShiftMe, Inc.">
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
    /// <summary>The ping federate authentication endpoints.</summary>
    public class PingFederateAuthenticationEndpoints
    {
        #region Public Properties

        /// <summary>
        ///     Gets or sets Endpoint which is used to redirect users to request PingFederate access
        /// </summary>
        /// <remarks>
        ///     Defaults to <see cref="PingFederateAuthenticationOptions.PingFederateUrl" />/as/authorization.oauth2
        /// </remarks>
        public string AuthorizationEndpoint { get; set; }

        /// <summary>
        ///     Gets or sets This public endpoint provides metadata needed for an OAuth client to interface with PingFederate using
        ///     the OpenID
        ///     Connect protocol.
        /// </summary>
        public string MetadataEndpoint { get; set; }

        /// <summary>
        ///     Gets or sets Endpoint which is used to exchange code for access token
        /// </summary>
        /// <remarks>
        ///     Defaults to /as/token.oauth2
        /// </remarks>
        public string TokenEndpoint { get; set; }

        /// <summary>
        ///     Gets or sets Endpoint which is used to obtain user information after authentication
        /// </summary>
        /// <remarks>
        ///     Defaults to /idp/userinfo.openid
        /// </remarks>
        public string UserInfoEndpoint { get; set; }

        #endregion
    }
}