// --------------------------------------------------------------------------------------------------------------------
// <copyright file="Constants.cs" company="ShiftMe, Inc.">
//   Copyright © 2015 ShiftMe, Inc.  All rights reserved.
// </copyright>
// <author>Alejandro Mora</author>
// --------------------------------------------------------------------------------------------------------------------
namespace Owin.Security.Providers.PingFederate
{
    /// <summary>The constants.</summary>
    internal static class Constants
    {
        #region Constants

        /// <summary>The default authentication type.</summary>
        public const string DefaultAuthenticationType = "PingFederate";

        #endregion

        /// <summary>The o auth 2 constants.</summary>
        public static class OAuth2Constants
        {
            #region Constants

            /// <summary>The access token.</summary>
            public const string AccessToken = "access_token";

            /// <summary>The acr values.</summary>
            public const string AcrValues = "acr_values";

            /// <summary>The assertion.</summary>
            public const string Assertion = "assertion";

            /// <summary>The client id.</summary>
            public const string ClientId = "client_id";

            /// <summary>The code.</summary>
            public const string Code = "code";

            /// <summary>The grant type.</summary>
            public const string GrantType = "grant_type";

            /// <summary>The identity token.</summary>
            public const string IdentityToken = "id_token";

            /// <summary>The idp adapter id.</summary>
            public const string IdpAdapterId = "pfidpadapterid";

            /// <summary>The nonce.</summary>
            public const string Nonce = "nonce";

            /// <summary>The partner idp id.</summary>
            public const string PartnerIdpId = "idp";

            /// <summary>The password.</summary>
            public const string Password = "password";

            /// <summary>The prompt.</summary>
            public const string Prompt = "prompt";

            /// <summary>The redirect uri.</summary>
            public const string RedirectUri = "redirect_uri";

            /// <summary>The refresh token.</summary>
            public const string RefreshToken = "refresh_token";

            /// <summary>The response type.</summary>
            public const string ResponseType = "response_type";

            /// <summary>The scope.</summary>
            public const string Scope = "scope";

            /// <summary>The state.</summary>
            public const string State = "state";

            /// <summary>The target url.</summary>
            public const string TargetUrl = "TargetUrl";

            /// <summary>The user name.</summary>
            public const string UserName = "username";

            #endregion

            /// <summary>The errors.</summary>
            public static class Errors
            {
                #region Constants

                /// <summary>The access denied.</summary>
                public const string AccessDenied = "access_denied";

                /// <summary>The error.</summary>
                public const string Error = "error";

                /// <summary>The invalid client.</summary>
                public const string InvalidClient = "invalid_client";

                /// <summary>The invalid grant.</summary>
                public const string InvalidGrant = "invalid_grant";

                /// <summary>The invalid request.</summary>
                public const string InvalidRequest = "invalid_request";

                /// <summary>The invalid scope.</summary>
                public const string InvalidScope = "invalid_scope";

                /// <summary>The unauthorized client.</summary>
                public const string UnauthorizedClient = "unauthorized_client";

                /// <summary>The unsupported grant type.</summary>
                public const string UnsupportedGrantType = "unsupported_grant_type";

                /// <summary>The unsupported response type.</summary>
                public const string UnsupportedResponseType = "unsupported_response_type";

                #endregion
            }

            /// <summary>The grant types.</summary>
            public static class GrantTypes
            {
                #region Constants

                /// <summary>The authorization code.</summary>
                public const string AuthorizationCode = "authorization_code";

                /// <summary>The client credentials.</summary>
                public const string ClientCredentials = "client_credentials";

                /// <summary>The jwt.</summary>
                public const string Jwt = "urn:ietf:params:oauth:grant-type:jwt-bearer";

                /// <summary>The password.</summary>
                public const string Password = "password";

                /// <summary>The refresh token.</summary>
                public const string RefreshToken = "refresh_token";

                /// <summary>The saml 2.</summary>
                public const string Saml2 = "urn:ietf:params:oauth:grant-type:saml2-bearer";

                /// <summary>The token validation.</summary>
                public const string TokenValidation = "urn:pingidentity.com:oauth2:grant_type:validate_bearer";

                #endregion
            }

            /// <summary>The response types.</summary>
            public static class ResponseTypes
            {
                #region Constants

                /// <summary>The code.</summary>
                public const string Code = "code";

                /// <summary>The token.</summary>
                public const string Token = "token";

                #endregion
            }
        }
    }
}