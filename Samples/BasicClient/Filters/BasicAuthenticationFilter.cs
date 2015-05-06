namespace BasicClient.Filters
{
    using System;
    using System.Web.Mvc;
    using System.Web.Mvc.Filters;

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method , Inherited = true, AllowMultiple = true)]
    public class BasicAuthenticationFilter : FilterAttribute, IAuthenticationFilter
    {
        /// <summary>
        /// Authenticates the request.
        /// </summary>
        /// <param name="filterContext">The context to use for authentication.</param>
        public void OnAuthentication(AuthenticationContext filterContext)
        {
            // Not needed
        }

        /// <summary>
        /// Adds an authentication challenge to the current <see cref="T:System.Web.Mvc.ActionResult"/>.
        /// </summary>
        /// <param name="filterContext">The context to use for the authentication challenge.</param>
        public void OnAuthenticationChallenge(AuthenticationChallengeContext filterContext)
        {
            var user = filterContext.HttpContext.User;

            if (!user.Identity.IsAuthenticated)
            {
                filterContext.Result = new HttpUnauthorizedResult();
            }
        }
    }
}