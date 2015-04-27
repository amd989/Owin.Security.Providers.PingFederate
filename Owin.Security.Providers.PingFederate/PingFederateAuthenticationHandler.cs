// --------------------------------------------------------------------------------------------------------------------
// <copyright file="PingFederateAuthenticationHandler.cs" company="ShiftMe, Inc.">
//   Copyright © 2015 ShiftMe, Inc.  All rights reserved.
// </copyright>
// <author>Alejandro Mora</author>
// --------------------------------------------------------------------------------------------------------------------
namespace Owin.Security.Providers.PingFederate
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security.Claims;
    using System.Text;
    using System.Threading.Tasks;

    using Microsoft.Owin.Infrastructure;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Infrastructure;

    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;

    using Owin.Security.Providers.PingFederate.Messages;
    using Owin.Security.Providers.PingFederate.Provider;

    /// <summary>The ping federate authentication handler.</summary>
    public class PingFederateAuthenticationHandler : AuthenticationHandler<PingFederateAuthenticationOptions>
    {
        #region Constants

        /// <summary>The xml schema string.</summary>
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

        #endregion

        #region Fields

        /// <summary>The http client.</summary>
        private readonly HttpClient httpClient;

        /// <summary>The logger.</summary>
        private readonly ILogger logger;

        #endregion

        #region Constructors and Destructors

        /// <summary>Initializes a new instance of the <see cref="PingFederateAuthenticationHandler"/> class.</summary>
        /// <param name="httpClient">The http client.</param>
        /// <param name="logger">The logger.</param>
        public PingFederateAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            this.httpClient = httpClient;
            this.logger = logger;
        }

        #endregion

        #region Public Methods and Operators

        /// <summary>
        ///     Called once by common code after initialization. If an authentication middleware responds directly to
        ///     specifically known paths it must override this virtual, compare the request path to it's known paths,
        ///     provide any response information as appropriate, and true to stop further processing.
        /// </summary>
        /// <returns>
        ///     Returning false will cause the common code to call the next middleware in line. Returning true will
        ///     cause the common code to begin the async completion journey without calling the rest of the middleware
        ///     pipeline.
        /// </returns>
        public override async Task<bool> InvokeAsync()
        {
            return await this.InvokeReplyPathAsync();
        }

        #endregion

        #region Methods

        /// <summary>The apply response challenge async.</summary>
        /// <returns>The <see cref="Task"/>.</returns>
        protected override async Task ApplyResponseChallengeAsync()
        {
            if (this.Response.StatusCode != 401)
            {
                return;
            }

            var challenge = this.Helper.LookupChallenge(
                this.Options.AuthenticationType, 
                this.Options.AuthenticationMode);

            if (challenge != null)
            {
                // Call Ping OpenIdConnect Metadata Endpoint to resolve values
                await this.DoMetadataDiscoveryAsync();

                var context = new PingFederateAuthenticatingContext(this.Context, this.Options);
                await this.Options.Provider.Authenticating(context);

                var baseUri = this.Request.Scheme + Uri.SchemeDelimiter + this.Request.Host + this.Request.PathBase;
                var currentUri = baseUri + this.Request.Path; // this.Request.QueryString; 
                var redirectUri = baseUri + this.Options.CallbackPath;

                var properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = currentUri;
                }

                // Add nonce
                var nonce = Guid.NewGuid().ToString();
                properties.Dictionary.Add("nonce", nonce);

                // OAuth2 10.12 CSRF
                this.GenerateCorrelationId(properties);

                // space separated
                var scope = string.Join(" ", this.Options.Scope);
                var acrValues = string.Join(" ", this.Options.AcrValues);

                var state = this.Options.StateDataFormat.Protect(properties);

                // Get prompt from current request
                var prompt = string.Empty;
                var query = this.Request.Query;
                var values = query.GetValues("prompt");
                if (values != null && values.Count == 1)
                {
                    prompt = values[0];
                }

                var explicitParameters = new Dictionary<string, string>
                                             {
                                                 { Constants.OAuth2Constants.ResponseType, Constants.OAuth2Constants.ResponseTypes.Code }, 
                                                 { Constants.OAuth2Constants.ClientId, Uri.EscapeDataString(this.Options.ClientId) }, 
                                                 { Constants.OAuth2Constants.RedirectUri, Uri.EscapeDataString(redirectUri) }, 
                                                 { Constants.OAuth2Constants.Scope, Uri.EscapeDataString(scope) }, 
                                                 { Constants.OAuth2Constants.State, Uri.EscapeDataString(state) }, 
                                                 { Constants.OAuth2Constants.PartnerIdpId, Uri.EscapeDataString(this.Options.PartnetIdpId ?? string.Empty) }, 
                                                 { Constants.OAuth2Constants.IdpAdapterId, Uri.EscapeDataString(this.Options.IdpAdapterId ?? string.Empty) }, 
                                                 { Constants.OAuth2Constants.Nonce, Uri.EscapeDataString(nonce) }, 
                                                 { Constants.OAuth2Constants.Prompt, Uri.EscapeDataString(prompt) }, 
                                                 { Constants.OAuth2Constants.AcrValues, Uri.EscapeDataString(acrValues) } 
                                             };

                var requestParameters = MergeAdditionalKeyValuePairsIntoExplicitKeyValuePairs(
                    explicitParameters, 
                    this.Options.AdditionalParameters);
                var authorizationEndpoint = this.Options.Endpoints.AuthorizationEndpoint
                                            + requestParameters.ToQueryString();
                this.Response.Redirect(authorizationEndpoint);
            }
        }

        /// <summary>The authenticate core async.</summary>
        /// <returns>The <see cref="Task"/>.</returns>
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                string code = null;
                string state = null;

                var query = this.Request.Query;
                var values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }

                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    state = values[0];
                }

                properties = this.Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!this.ValidateCorrelationId(properties, this.logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                // Set information for current request in case is missing
                if (string.IsNullOrEmpty(this.Options.Endpoints.TokenEndpoint))
                {
                    await this.DoMetadataDiscoveryAsync();
                }

                // Call on token request
                var tokenRequestContext = new PingFederateTokenRequestContext(this.Context, this.Options, state, code, properties);
                await this.Options.Provider.TokenRequest(tokenRequestContext);

                var requestPrefix = this.Request.Scheme + Uri.SchemeDelimiter + this.Request.Host + this.Request.PathBase;
                var redirectUri = requestPrefix + Options.CallbackPath;

                // Build up the body for the token request
                var body = new List<KeyValuePair<string, string>>
                               {
                                   new KeyValuePair<string, string>(Constants.OAuth2Constants.GrantType, Constants.OAuth2Constants.GrantTypes.AuthorizationCode),
                                   new KeyValuePair<string, string>(Constants.OAuth2Constants.Code, code), 
                                   new KeyValuePair<string, string>(Constants.OAuth2Constants.RedirectUri, redirectUri)
                               };

                var isClientSecretEmpty = string.IsNullOrEmpty(this.Options.ClientSecret);
                if (isClientSecretEmpty)
                {
                    body.Add(
                        new KeyValuePair<string, string>(Constants.OAuth2Constants.ClientId, this.Options.ClientId));
                }

                // Request the token
                var requestMessage = new HttpRequestMessage(HttpMethod.Post, this.Options.Endpoints.TokenEndpoint);
                if (!isClientSecretEmpty)
                {
                    requestMessage.Headers.Authorization = new AuthenticationHeaderValue(
                        "Basic", 
                        EncodeCredential(this.Options.ClientId, this.Options.ClientSecret));
                }

                requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                requestMessage.Content = new FormUrlEncodedContent(body);
                var tokenResponse = await this.httpClient.SendAsync(requestMessage);
                tokenResponse.EnsureSuccessStatusCode();
                var text = await tokenResponse.Content.ReadAsStringAsync();

                // Deserializes the token response
                var response = JsonConvert.DeserializeObject<dynamic>(text);
                var accessToken = (string)response.access_token;
                string identityToken = response.id_token;
                string refreshToken = null;
                if (response.refresh_token != null)
                {
                    refreshToken = (string)response.refresh_token;
                }

                // Get the PingFederate user
                JObject user = null;
                if (this.Options.RequestUserInfo)
                {
                    var userRequest = new HttpRequestMessage(HttpMethod.Post, this.Options.Endpoints.UserInfoEndpoint);
                    userRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                    var formEncoded = new FormUrlEncodedContent(new Dictionary<string, string> { { Constants.OAuth2Constants.AccessToken, accessToken } });
                    userRequest.Content = formEncoded;
                    var userResponse = await this.httpClient.SendAsync(userRequest, this.Request.CallCancelled);
                    userResponse.EnsureSuccessStatusCode();
                    text = await userResponse.Content.ReadAsStringAsync();
                    user = JObject.Parse(text);
                }

                // Create Context
                var context = new PingFederateAuthenticatedContext(this.Context, user, accessToken, identityToken, refreshToken)
                                  {
                                      Identity =
                                          new ClaimsIdentity(
                                          this.Options.AuthenticationType, 
                                          ClaimsIdentity.DefaultNameClaimType, 
                                          ClaimsIdentity.DefaultRoleClaimType)
                                  };
                
                if (!string.IsNullOrEmpty(context.Id))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString, this.Options.AuthenticationType));
                }

                if (!string.IsNullOrEmpty(context.UserName))
                {
                    context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.UserName, XmlSchemaString, this.Options.AuthenticationType));
                }

                if (!string.IsNullOrEmpty(context.Email))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, XmlSchemaString, this.Options.AuthenticationType));
                }

                if (!string.IsNullOrEmpty(context.Name))
                {
                    context.Identity.AddClaim(new Claim("urn:pingfederate:name", context.Name, XmlSchemaString, this.Options.AuthenticationType));
                }

                if (!string.IsNullOrEmpty(context.Link))
                {
                    context.Identity.AddClaim(new Claim("urn:pingfederate:url", context.Link, XmlSchemaString, this.Options.AuthenticationType));
                }

                if (!string.IsNullOrEmpty(accessToken))
                {
                    context.Identity.AddClaim(new Claim(Constants.OAuth2Constants.AccessToken, accessToken, XmlSchemaString, this.Options.AuthenticationType));
                }

                if (!string.IsNullOrEmpty(identityToken))
                {
                    context.Identity.AddClaim(new Claim(Constants.OAuth2Constants.IdentityToken, identityToken, XmlSchemaString, this.Options.AuthenticationType));
                }

                if (!string.IsNullOrEmpty(refreshToken))
                {
                    context.Identity.AddClaim(new Claim(Constants.OAuth2Constants.RefreshToken, refreshToken, XmlSchemaString, this.Options.AuthenticationType));
                }

                if (!string.IsNullOrEmpty(redirectUri))
                {
                    context.Identity.AddClaim(new Claim(Constants.OAuth2Constants.TargetUrl, redirectUri, XmlSchemaString, this.Options.AuthenticationType));
                }

                context.Properties = properties;

                await this.Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                this.logger.WriteError(ex.Message);
            }

            return new AuthenticationTicket(null, properties);
        }

        /// <summary>The encode credential.</summary>
        /// <param name="userName">The user name.</param>
        /// <param name="password">The password.</param>
        /// <returns>The <see cref="string"/>.</returns>
        private static string EncodeCredential(string userName, string password)
        {
            var encoding = Encoding.GetEncoding("iso-8859-1");
            var credential = string.Format("{0}:{1}", userName, password);
            return Convert.ToBase64String(encoding.GetBytes(credential));
        }

        /// <summary>Merges additional into explicit properties keeping all explicit properties intact</summary>
        /// <param name="explicitProperties">The explicit Properties.</param>
        /// <param name="additionalProperties">The additional Properties.</param>
        /// <returns>The <see cref="Dictionary{String,String}"/>.</returns>
        private static Dictionary<string, string> MergeAdditionalKeyValuePairsIntoExplicitKeyValuePairs(
            Dictionary<string, string> explicitProperties, 
            Dictionary<string, string> additionalProperties = null)
        {
            var merged = explicitProperties;

            // no need to iterate if additional is null
            if (additionalProperties != null)
            {
                merged =
                    explicitProperties.Concat(
                        additionalProperties.Where(add => !explicitProperties.ContainsKey(add.Key)))
                        .Where(a => !string.IsNullOrEmpty(a.Value))
                        .ToDictionary(final => final.Key, final => final.Value);
            }

            return merged;
        }

        /// <summary>The do metadata discovery async.</summary>
        /// <returns>The <see cref="Task"/>.</returns>
        private async Task DoMetadataDiscoveryAsync()
        {
            if (!string.IsNullOrEmpty(this.Options.Endpoints.MetadataEndpoint))
            {
                var response = await this.httpClient.GetStringAsync(this.Options.Endpoints.MetadataEndpoint);
                var endpoints = JsonConvert.DeserializeObject<MetadataEndpoints>(response);
                this.Options.Endpoints.AuthorizationEndpoint = endpoints.AuthorizationEndpoint;
                this.Options.Endpoints.TokenEndpoint = endpoints.TokenEndpoint;
                this.Options.Endpoints.UserInfoEndpoint = endpoints.UserInfoEndpoint;
            }
        }

        /// <summary>The invoke reply path async.</summary>
        /// <returns>The <see cref="Task"/>.</returns>
        private async Task<bool> InvokeReplyPathAsync()
        {
            var callBack = this.Options.CallbackPath;
            if (callBack.HasValue && this.Request.Path.Value.Contains(callBack.Value))
            {
                // TODO: error responses
                var ticket = await this.AuthenticateAsync();
                if (ticket == null)
                {
                    this.logger.WriteWarning("Invalid return state, unable to redirect.");
                    this.Response.StatusCode = 500;
                    return true;
                }

                var context = new PingFederateReturnEndpointContext(this.Context, ticket)
                                  {
                                      SignInAsAuthenticationType = this.Options.SignInAsAuthenticationType,
                                      RedirectUri = ticket.Properties.RedirectUri
                                  };

                await this.Options.Provider.ReturnEndpoint(context);

                if (context.SignInAsAuthenticationType != null && context.Identity != null)
                {
                    var grantIdentity = context.Identity;
                    if (
                        !string.Equals(
                            grantIdentity.AuthenticationType, 
                            context.SignInAsAuthenticationType, 
                            StringComparison.Ordinal))
                    {
                        grantIdentity = new ClaimsIdentity(
                            grantIdentity.Claims, 
                            context.SignInAsAuthenticationType, 
                            grantIdentity.NameClaimType, 
                            grantIdentity.RoleClaimType);
                    }

                    this.Context.Authentication.SignIn(context.Properties, grantIdentity);
                }

                if (!context.IsRequestCompleted && context.RedirectUri != null)
                {
                    var redirectUri = context.RedirectUri;
                    if (context.Identity == null)
                    {
                        // add a redirect hint that sign-in failed in some way
                        redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
                    }

                    this.Response.Redirect(redirectUri);
                    context.RequestCompleted();
                }

                return context.IsRequestCompleted;
            }

            return false;
        }

        #endregion
    }
}