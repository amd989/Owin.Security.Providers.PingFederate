// --------------------------------------------------------------------------------------------------------------------
// <copyright file="FilterConfig.cs" company="">
//   
// </copyright>
// <summary>
//   Defines the FilterConfig type.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace OwinOpenIdMiddleware
{
    using System.Web.Mvc;

    public class FilterConfig
    {
        /// <summary>The register global filters.</summary>
        /// <param name="filters">The filters.</param>
        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            filters.Add(new HandleErrorAttribute());
            filters.Add(new AuthorizeAttribute());
        }
    }
}
