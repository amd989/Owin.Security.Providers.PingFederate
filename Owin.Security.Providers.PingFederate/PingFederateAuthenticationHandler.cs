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
    using Microsoft.Owin;
    using Microsoft.Owin.Infrastructure;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Infrastructure;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;

    using Owin.Security.Providers.PingFederate.Messages;
    using Owin.Security.Providers.PingFederate.Provider;

    public class PingFederateAuthenticationHandler : AuthenticationHandler<PingFederateAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

        private readonly ILogger logger;
        private readonly HttpClient httpClient;

        public PingFederateAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            this.httpClient = httpClient;
            this.logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                string code = null;
                string state = null;

                IReadableStringCollection query = Request.Query;
                IList<string> values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }

                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    state = values[0];
                }

                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, this.logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                string requestPrefix = Request.Scheme + "://" + Request.Host;
                string redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

                // Build up the body for the token request
                var body = new List<KeyValuePair<string, string>>();
                body.Add(new KeyValuePair<string, string>(Constants.OAuth2Constants.GrantType, Constants.OAuth2Constants.GrantTypes.AuthorizationCode));
                body.Add(new KeyValuePair<string, string>(Constants.OAuth2Constants.Code, code));
                body.Add(new KeyValuePair<string, string>(Constants.OAuth2Constants.RedirectUri, redirectUri));
                
                var isClientSecretEmpty = string.IsNullOrEmpty(Options.ClientSecret);
                if (isClientSecretEmpty)
                {
                    body.Add(new KeyValuePair<string, string>(Constants.OAuth2Constants.ClientId, Options.ClientId));
                }

                // Request the token
                var requestMessage = new HttpRequestMessage(HttpMethod.Post, Options.Endpoints.TokenEndpoint);
                if (!isClientSecretEmpty)
                {
                    requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Basic", EncodeCredential(Options.ClientId, Options.ClientSecret));
                }

                requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                requestMessage.Content = new FormUrlEncodedContent(body);
                HttpResponseMessage tokenResponse = await this.httpClient.SendAsync(requestMessage);
                tokenResponse.EnsureSuccessStatusCode();
                string text = await tokenResponse.Content.ReadAsStringAsync();

                // Deserializes the token response
                dynamic response = JsonConvert.DeserializeObject<dynamic>(text);
                string accessToken = (string)response.access_token;
                string identityToken = response.identity_token;
                string refreshToken = null;
                if (response.refresh_token != null)
                    refreshToken = (string)response.refresh_token;

                // Get the PingFederate user
                JObject user = null;
                if (Options.RequestUserInfo)
                {
                    var userRequest = new HttpRequestMessage(HttpMethod.Post, Options.Endpoints.UserInfoEndpoint);
                    userRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                    var formEncoded = new FormUrlEncodedContent(new Dictionary<string, string> { { Constants.OAuth2Constants.AccessToken, accessToken } });
                    userRequest.Content = formEncoded;
                    HttpResponseMessage userResponse = await this.httpClient.SendAsync(userRequest, Request.CallCancelled);
                    userResponse.EnsureSuccessStatusCode();
                    text = await userResponse.Content.ReadAsStringAsync();
                    user = JObject.Parse(text);
                }

                // Create Context
                var context = new PingFederateAuthenticatedContext(this.Context, user, accessToken, identityToken, refreshToken);
                context.Identity = new ClaimsIdentity(
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);
                
                if (!string.IsNullOrEmpty(context.Id))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.UserName))
                {
                    context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.UserName, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Email))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Name))
                {
                    context.Identity.AddClaim(new Claim("urn:pingfederate:name", context.Name, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Link))
                {
                    context.Identity.AddClaim(new Claim("urn:pingfederate:url", context.Link, XmlSchemaString, Options.AuthenticationType));
                }
                context.Properties = properties;

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                this.logger.WriteError(ex.Message);
            }
            return new AuthenticationTicket(null, properties);
        }

        protected override async Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return;
            }

            var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                if (string.IsNullOrEmpty(Options.Endpoints.MetadataEndpoint))
                {
                    await this.DoMetadataDiscoveryAsync();
                }

                string baseUri =
                    Request.Scheme +
                    Uri.SchemeDelimiter +
                    Request.Host +
                    Request.PathBase;

                string currentUri =
                    baseUri +
                    Request.Path +
                    Request.QueryString;

                string redirectUri =
                    baseUri +
                    Options.CallbackPath;

                AuthenticationProperties properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = currentUri;
                }
                
                // Add nonce
                var nonce = Guid.NewGuid().ToString();
                properties.Dictionary.Add("nonce", nonce);

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(properties);

                // space separated
                string scope = string.Join(" ", Options.Scope);
                string acrValues = string.Join(" ", Options.AcrValues);
                
                string state = Options.StateDataFormat.Protect(properties);

                // Get prompt from current request
                var prompt = string.Empty;
                var query = Request.Query;
                var values = query.GetValues("prompt");
                if (values != null && values.Count == 1)
                {
                    prompt = values[0];
                }

                var explicitParameters = new Dictionary<string, string>
                                             {
                                                 { Constants.OAuth2Constants.ResponseType, Constants.OAuth2Constants.ResponseTypes.Code },
                                                 { Constants.OAuth2Constants.ClientId, Uri.EscapeDataString(Options.ClientId)},
                                                 { Constants.OAuth2Constants.RedirectUri, Uri.EscapeDataString(redirectUri) },
                                                 { Constants.OAuth2Constants.Scope, Uri.EscapeDataString(scope) },
                                                 { Constants.OAuth2Constants.State, Uri.EscapeDataString(state) },
                                                 { Constants.OAuth2Constants.PartnerIdpId, Uri.EscapeDataString(Options.PartnetIdpId) },
                                                 { Constants.OAuth2Constants.IdpAdapterId, Uri.EscapeDataString(Options.IdpAdapterId) },
                                                 { Constants.OAuth2Constants.Nonce, Uri.EscapeDataString(nonce) },
                                                 { Constants.OAuth2Constants.Prompt, Uri.EscapeDataString(prompt) },
                                                 { Constants.OAuth2Constants.AcrValues, Uri.EscapeDataString(acrValues) },
                                             };

                var requestParameters = MergeAdditionalKeyValuePairsIntoExplicitKeyValuePairs(explicitParameters, Options.AdditionalParameters);
                var authorizationEndpoint = Options.Endpoints.AuthorizationEndpoint + requestParameters.ToQueryString();
                Response.Redirect(authorizationEndpoint);
            }
        }
        
        private async Task DoMetadataDiscoveryAsync()
        {
            var response =  await this.httpClient.GetStringAsync(Options.Endpoints.MetadataEndpoint);
            var endpoints = JsonConvert.DeserializeObject<MetadataEndpoints>(response);
            Options.Endpoints.AuthorizationEndpoint = endpoints.AuthorizationEndpoint;
            Options.Endpoints.TokenEndpoint = endpoints.TokenEndpoint;
            Options.Endpoints.UserInfoEndpoint = endpoints.UserInfoEndpoint;
        }

        private static string EncodeCredential(string userName, string password)
        {
            Encoding encoding = Encoding.GetEncoding("iso-8859-1");
            string credential = String.Format("{0}:{1}", userName, password);

            return Convert.ToBase64String(encoding.GetBytes(credential));
        }

        /// <summary>
        /// Merges additional into explicit properties keeping all explicit properties intact
        /// </summary>
        /// <param name="explicitProperties"></param>
        /// <param name="additionalProperties"></param>
        /// <returns></returns>
        private static Dictionary<string, string> MergeAdditionalKeyValuePairsIntoExplicitKeyValuePairs(
            Dictionary<string, string> explicitProperties, Dictionary<string, string> additionalProperties = null)
        {
            Dictionary<string, string> merged = explicitProperties;
            //no need to iterate if additional is null
            if (additionalProperties != null)
            {
                merged =
                    explicitProperties.Concat(additionalProperties.Where(add => !explicitProperties.ContainsKey(add.Key)))
                                         .ToDictionary(final => final.Key, final => final.Value);
            }
            return merged;
        }

        public override async Task<bool> InvokeAsync()
        {
            return await this.InvokeReplyPathAsync();
        }

        private async Task<bool> InvokeReplyPathAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                // TODO: error responses

                AuthenticationTicket ticket = await AuthenticateAsync();
                if (ticket == null)
                {
                    this.logger.WriteWarning("Invalid return state, unable to redirect.");
                    Response.StatusCode = 500;
                    return true;
                }

                var context = new PingFederateReturnEndpointContext(Context, ticket);
                context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
                context.RedirectUri = ticket.Properties.RedirectUri;

                await Options.Provider.ReturnEndpoint(context);

                if (context.SignInAsAuthenticationType != null &&
                    context.Identity != null)
                {
                    ClaimsIdentity grantIdentity = context.Identity;
                    if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                    {
                        grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                    }

                    Context.Authentication.SignIn(context.Properties, grantIdentity);
                }

                if (!context.IsRequestCompleted && context.RedirectUri != null)
                {
                    string redirectUri = context.RedirectUri;
                    if (context.Identity == null)
                    {
                        // add a redirect hint that sign-in failed in some way
                        redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
                    }
                    Response.Redirect(redirectUri);
                    context.RequestCompleted();
                }

                return context.IsRequestCompleted;
            }
            return false;
        }
    }
}