using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.Mvc;
using Microsoft.Owin.Security;
using MVCIdentity.App.Util.Extensions;

namespace MVCIdentity.App.Controllers
{
    [Authorize]
    public class HomeController : IdentityController
    {
        public ActionResult Index()
        {
            ViewBag.EmailAuth = User.Identity.GetEmailAdress(Context);

            return View();
        }

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