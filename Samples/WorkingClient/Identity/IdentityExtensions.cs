// --------------------------------------------------------------------------------------------------------------------
// <copyright file="IdentityExtensions.cs" company="">
//   
// </copyright>
// <summary>
//   The identity extensions.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace OwinOpenIdMiddleware.Identity
{
    using System;
    using System.Globalization;
    using System.Security.Claims;
    using System.Security.Principal;

    using Microsoft.AspNet.Identity;

    /// <summary>The identity extensions.</summary>
    public static class IdentityExtensions
    {
        /// <summary>
        ///     Return the user name using the UserNameClaimType
        /// </summary>
        /// <param name="identity"></param>
        /// <returns></returns>
        public static string GetName(this IIdentity identity)
        {
            if (identity == null)
            {
                throw new ArgumentNullException("identity");
            }

            var ci = identity as ClaimsIdentity;
            if (ci != null)
            {
                return string.Format(CultureInfo.InvariantCulture, "{0} {1}", ci.FindFirstValue("FirstName"), ci.FindFirstValue("LastName"));
            }

            return null;
        }
    }
}