// --------------------------------------------------------------------------------------------------------------------
// <copyright file="ErrorController.cs" company="">
//   
// </copyright>
//  <summary>
//   ErrorController.cs
// </summary>
// <author>alejandro.mora\Alejandro Mora</author>
// --------------------------------------------------------------------------------------------------------------------

namespace OwinOpenIdMiddleware.Controllers
{
    using System.Web.Mvc;

    /// <summary>The error controller.</summary>
    [AllowAnonymous]
    public class ErrorController : Controller
    {
        // GET: Error
        #region Public Methods and Operators

        /// <summary>The login failure.</summary>
        /// <param name="error">The error.</param>
        /// <param name="error_description">The error_description.</param>
        /// <returns>The <see cref="ActionResult"/>.</returns>
        public ActionResult LoginFailure(string error, string error_description)
        {
            ViewBag.Error = error;
            ViewBag.ErrorDetails = error_description;
            return this.View();
        }

        #endregion
    }
}