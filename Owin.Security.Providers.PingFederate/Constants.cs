namespace Owin.Security.Providers.PingFederate
{
    internal static class Constants
    {
        public const string DefaultAuthenticationType = "PingFederate";

        public static class OAuth2Constants
        {
            public const string GrantType = "grant_type";
            public const string UserName = "username";
            public const string Scope = "scope";
            public const string State = "state";
            public const string Nonce = "nonce";
            public const string Prompt = "prompt";
            public const string AcrValues = "acr_values";
            public const string AccessToken = "access_token";
            public const string PartnerIdpId = "idp";
            public const string IdpAdapterId = "pfidpadapterid";
            public const string Assertion = "assertion";
            public const string Password = "password";
            public const string Code = "code";
            public const string RedirectUri = "redirect_uri";
            public const string ClientId = "client_id";
            public const string ResponseType = "response_type";

            public static class GrantTypes
            {
                public const string Password = "password";
                public const string AuthorizationCode = "authorization_code";
                public const string ClientCredentials = "client_credentials";
                public const string RefreshToken = "refresh_token";
                public const string JWT = "urn:ietf:params:oauth:grant-type:jwt-bearer";
                public const string Saml2 = "urn:ietf:params:oauth:grant-type:saml2-bearer";
                public const string TokenValidation = "urn:pingidentity.com:oauth2:grant_type:validate_bearer";
            }

            public static class ResponseTypes
            {
                public const string Token = "token";
                public const string Code = "code";
            }

            public static class Errors
            {
                public const string Error = "error";
                public const string InvalidRequest = "invalid_request";
                public const string InvalidClient = "invalid_client";
                public const string InvalidGrant = "invalid_grant";
                public const string UnauthorizedClient = "unauthorized_client";
                public const string UnsupportedGrantType = "unsupported_grant_type";
                public const string UnsupportedResponseType = "unsupported_response_type";
                public const string InvalidScope = "invalid_scope";
                public const string AccessDenied = "access_denied";
            }

            
        }
    }
}