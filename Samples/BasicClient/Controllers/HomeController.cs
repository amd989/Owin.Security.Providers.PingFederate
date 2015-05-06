using System.Web.Mvc;

namespace BasicClient.Controllers
{
    using BasicClient.Filters;

    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        [BasicAuthenticationFilter]
        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}