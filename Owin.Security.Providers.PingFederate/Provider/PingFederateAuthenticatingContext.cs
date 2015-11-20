// --------------------------------------------------------------------------------------------------------------------
// <copyright file="PingFederateAuthenticatingContext.cs" company="ShiftMe, Inc.">
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

namespace Owin.Security.Providers.PingFederate.Provider
{
    using Microsoft.Owin;
    using Microsoft.Owin.Security.Provider;

    /// <summary>
    ///     The ping federate authenticating context.
    /// </summary>
    public class PingFederateAuthenticatingContext : BaseContext
    {
        #region Constructors and Destructors

        /// <summary>Initializes a new instance of the <see cref="PingFederateAuthenticatingContext"/> class.</summary>
        /// <param name="context">The context.</param>
        /// <param name="options">The options.</param>
        public PingFederateAuthenticatingContext(IOwinContext context, PingFederateAuthenticationOptions options)
            : base(context)
        {
            this.Context = context;
            this.Options = options;
        }

        #endregion

        #region Public Properties

        /// <summary>
        ///     Gets or sets the context.
        /// </summary>
        public IOwinContext Context { get; set; }

        /// <summary>
        ///     Gets or sets the options.
        /// </summary>
        public PingFederateAuthenticationOptions Options { get; set; }

        #endregion
    }
}