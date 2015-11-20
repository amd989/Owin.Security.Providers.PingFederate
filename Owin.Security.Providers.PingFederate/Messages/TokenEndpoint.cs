// --------------------------------------------------------------------------------------------------------------------
// <copyright file="TokenEndpoint.cs" company="ShiftMe, Inc.">
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

namespace Owin.Security.Providers.PingFederate.Messages
{
    using Newtonsoft.Json;

    /// <summary>The token endpoint.</summary>
    public class TokenEndpoint
    {
        #region Public Properties

        /// <summary>Gets or sets the access token.</summary>
        [JsonProperty(PropertyName = "access_token")]
        public string AccessToken { get; set; }

        /// <summary>Gets or sets the error.</summary>
        [JsonProperty(PropertyName = "error")]
        public string Error { get; set; }

        /// <summary>Gets or sets the error description.</summary>
        [JsonProperty(PropertyName = "error_description")]
        public string ErrorDescription { get; set; }

        /// <summary>Gets or sets the id token.</summary>
        [JsonProperty(PropertyName = "id_token")]
        public string IdToken { get; set; }

        /// <summary>Gets or sets the refresh token.</summary>
        [JsonProperty(PropertyName = "refresh_token")]
        public string RefreshToken { get; set; }

        #endregion
    }
}