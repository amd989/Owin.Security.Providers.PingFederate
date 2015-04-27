// --------------------------------------------------------------------------------------------------------------------
// <copyright file="PingFederateAuthenticationOptions.cs" company="ShiftMe, Inc.">
//   Copyright © 2015 ShiftMe, Inc.  All rights reserved.
// </copyright>
// <author>Alejandro Mora</author>
// --------------------------------------------------------------------------------------------------------------------
namespace Owin.Security.Providers.PingFederate
{
    using System;
    using System.Collections.Generic;
    using System.Net.Http;

    using Microsoft.Owin;
    using Microsoft.Owin.Security;

    using Owin.Security.Providers.PingFederate.Provider;

    /// <summary>The ping federate authentication options.</summary>
    public class PingFederateAuthenticationOptions : AuthenticationOptions
    {
        #region Constants

        /// <summary>The authorization end point.</summary>
        public const string AuthorizationEndPoint = "/as/authorization.oauth2";

        /// <summary>The open id connect metadata endpoint.</summary>
        public const string OpenIdConnectMetadataEndpoint = "/.well-known/openid-configuration";

        /// <summary>The token endpoint.</summary>
        public const string TokenEndpoint = "/as/token.oauth2";

        /// <summary>The user info endpoint.</summary>
        public const string UserInfoEndpoint = "/idp/userinfo.openid";

        #endregion

        #region Constructors and Destructors

        /// <summary>Initializes a new instance of the <see cref="PingFederateAuthenticationOptions" /> class.</summary>
        public PingFederateAuthenticationOptions()
            : base("PingFederate")
        {
            this.Caption = Constants.DefaultAuthenticationType;
            this.CallbackPath = new PathString("/signin-pingfederate");
            this.PartnetIdpId = string.Empty;
            this.AuthenticationMode = AuthenticationMode.Passive;
            this.Scope = new List<string> { "openid" };
            this.BackchannelTimeout = TimeSpan.FromSeconds(60);
            this.Endpoints = new PingFederateAuthenticationEndpoints();
            this.RequestUserInfo = true;
        }

        #endregion

        #region Public Properties

        /// <summary>
        ///     Gets or sets the Authentication Context Class Reference (acr) values for the AS to use when processing an
        ///     Authentication Request. Express as a space-separated string, listing the values in order of preference.
        /// </summary>
        public string AcrValues { get; set; }

        /// <summary>
        ///     Gets or sets additional values set in this property will be appended to the authorization request.
        /// </summary>
        public Dictionary<string, string> AdditionalParameters { get; set; }

        /// <summary>
        ///     Gets or sets the a pinned certificate validator to use to validate the endpoints used
        ///     in back channel communications belong to PingFederate.
        /// </summary>
        /// <value>
        ///     The pinned certificate validator.
        /// </value>
        /// <remarks>
        ///     If this property is null then the default certificate checks are performed,
        ///     validating the subject name and if the signing chain is a trusted party.
        /// </remarks>
        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        /// <summary>
        ///     Gets or sets the HttpMessageHandler used to communicate with PingFederate.
        ///     This cannot be set at the same time as BackchannelCertificateValidator unless the value
        ///     can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        ///     Gets or sets timeout value in milliseconds for back channel communications with PingFederate.
        /// </summary>
        /// <value>
        ///     The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        ///     Gets or sets the request path within the application's base path where the user-agent will be returned.
        ///     The middleware will process this request when it arrives.
        ///     Default value is "/signin-pingfederate".
        /// </summary>
        public PathString CallbackPath { get; set; }

        /// <summary>
        ///     Gets or sets the text that the user can display on a sign in user interface.
        /// </summary>
        public string Caption
        {
            get
            {
                return this.Description.Caption;
            }

            set
            {
                this.Description.Caption = value;
            }
        }

        /// <summary>
        ///     Gets or sets the PingFederate supplied Client ID
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        ///     Gets or sets the PingFederate supplied Client Secret
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        ///     Gets or sets the OAuth endpoints used to authenticate against PingFederate.  Overriding these endpoints allows you
        ///     to use PingFederate Enterprise for
        ///     authentication.
        /// </summary>
        public PingFederateAuthenticationEndpoints Endpoints { get; set; }

        /// <summary>
        ///     Gets or sets the PingFederate OAuth AS parameter indicating the IdP Adapter Instance ID of the adapter to use for user
        ///     authentication.
        /// </summary>
        /// <remarks>
        ///     This parameter may be overridden by policy based on adapter selector configuration. For example, the OAuth Scope
        ///     Selector could enforce the use of a given adapter based on client-requested scopes
        /// </remarks>
        public string IdpAdapterId { get; set; }

        /// <summary>
        ///     Gets or sets a PingFederate OAuth AS parameter indicating the Entity ID/Connection ID of the IdP with whom to initiate Browser
        ///     SSO for user authentication.
        /// </summary>
        public string PartnetIdpId { get; set; }

        /// <summary>
        ///     Gets or sets the PingFederate server URL
        /// </summary>
        public string PingFederateUrl { get; set; }

        /// <summary>
        ///     Gets or sets the <see cref="IPingFederateAuthenticationProvider" /> used in the authentication events
        /// </summary>
        public IPingFederateAuthenticationProvider Provider { get; set; }

        /// <summary>Gets or sets the authentication handler.</summary>
        public IPingFederateAuthenticationHandlerFactory AuthenticationHandlerFactory { get; set; }

        /// <summary>Gets or sets a value indicating whether to request user info.</summary>
        public bool RequestUserInfo { get; set; }

        /// <summary>
        ///     Gets or sets a list of permissions to request.
        /// </summary>
        public IList<string> Scope { get; set; }

        /// <summary>
        ///     Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user
        ///     <see cref="System.Security.Claims.ClaimsIdentity" />.
        /// </summary>
        public string SignInAsAuthenticationType { get; set; }

        /// <summary>
        ///     Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        #endregion

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
            ///     Gets or sets This public endpoint provides metadata needed for an OAuth client to interface with PingFederate using the OpenID
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
}