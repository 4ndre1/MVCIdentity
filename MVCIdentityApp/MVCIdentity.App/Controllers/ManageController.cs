using System;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using MVCIdentity.App.Util.Extensions;
using MVCIdentity.Identity.Model;

namespace MVCIdentity.App.Controllers
{
    [Authorize]
    public class ManageController : IdentityController
    {
        private static string _emailUsuario;

        public ManageController() : base()
        {
        }

        private string GetEmailAdress()
        {
            if (string.IsNullOrWhiteSpace(_emailUsuario))
            {
                _emailUsuario = User.Identity.GetEmailAdress(Context);
                return _emailUsuario;
            }

            return _emailUsuario;
        }

        //
        // GET: /Manage/Index
        public async Task<ActionResult> Index(ManageMessageId? message)
        {
            ViewBag.StatusMessage =
                message == ManageMessageId.ChangePasswordSuccess ? "Sua senha foi trocada."
                : message == ManageMessageId.SetPasswordSuccess ? "Sua senha foi setada."
                : message == ManageMessageId.SetTwoFactorSuccess ? "Autenticação de fatores foi setada com sucesso."
                : message == ManageMessageId.Error ? "Um erro ocorreu."
                : message == ManageMessageId.AddPhoneSuccess ? "Seu número de telefone foi adicionado."
                : message == ManageMessageId.RemovePhoneSuccess ? "Seu número de telefone foi removido."
                : "";

            var userId = int.Parse(User.Identity.GetUserId());
            var model = new IndexViewModel
            {
                HasPassword = HasPassword(),
                PhoneNumber = await UserManager.GetPhoneNumberAsync(userId),
                TwoFactor = await UserManager.GetTwoFactorEnabledAsync(userId),
                Logins = await UserManager.GetLoginsAsync(userId),
                BrowserRemembered = await AuthenticationManager.TwoFactorBrowserRememberedAsync(userId.ToString())
            };

            ViewBag.EmailAuth = GetEmailAdress();

            return View(model);
        }

        //
        // POST: /Manage/RemoveLogin
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> RemoveLogin(string loginProvider, string providerKey)
        {
            ManageMessageId? message;
            var id = Convert.ToInt32(User.Identity.GetUserId());

            var result = await UserManager.RemoveLoginAsync(id, new UserLoginInfo(loginProvider, providerKey));
            if (result.Succeeded)
            {
                var user = await UserManager.FindByIdAsync(id);
                if (user != null)
                {
                    await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                }
                message = ManageMessageId.RemoveLoginSuccess;
            }
            else
            {
                message = ManageMessageId.Error;
            }
            return RedirectToAction("ManageLogins", new { Message = message });
        }

        //
        // GET: /Manage/AddPhoneNumber
        public ActionResult AddPhoneNumber()
        {
            ViewBag.EmailAuth = GetEmailAdress();

            return View();
        }

        //
        // POST: /Manage/AddPhoneNumber
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> AddPhoneNumber(AddPhoneNumberViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var id = Convert.ToInt32(User.Identity.GetUserId());

            // Generate the token and send it
            var code = await UserManager.GenerateChangePhoneNumberTokenAsync(id, model.NumeroCelular);
            if (UserManager.SmsService != null)
            {
                var message = new IdentityMessage
                {
                    Destination = model.NumeroCelular,
                    Body = "Seu codigo de seguranca e: " + code
                };

                try
                {
                    await UserManager.SmsService.SendAsync(message);
                }
                catch (Exception e)
                {
                    ModelState.AddModelError("", e.Message);
                    return View("AddPhoneNumber");
                }

            }
            return RedirectToAction("VerifyPhoneNumber", new { PhoneNumber = model.NumeroCelular });
        }

        //
        // POST: /Manage/EnableTwoFactorAuthentication
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> EnableTwoFactorAuthentication()
        {
            var id = Convert.ToInt32(User.Identity.GetUserId());

            await UserManager.SetTwoFactorEnabledAsync(id, true);
            var user = await UserManager.FindByIdAsync(id);
            if (user != null)
            {
                await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
            }
            return RedirectToAction("Index", "Manage");
        }

        //
        // POST: /Manage/DisableTwoFactorAuthentication
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> DisableTwoFactorAuthentication()
        {
            var id = Convert.ToInt32(User.Identity.GetUserId());

            await UserManager.SetTwoFactorEnabledAsync(id, false);
            var user = await UserManager.FindByIdAsync(id);
            if (user != null)
            {
                await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
            }
            return RedirectToAction("Index", "Manage");
        }

        //
        // GET: /Manage/VerifyPhoneNumber
        public async Task<ActionResult> VerifyPhoneNumber(string phoneNumber)
        {
            var id = Convert.ToInt32(User.Identity.GetUserId());

            var code = await UserManager.GenerateChangePhoneNumberTokenAsync(id, phoneNumber);
            // Send an SMS through the SMS provider to verify the phone number
            return phoneNumber == null ? View("Error") : View(new VerifyPhoneNumberViewModel { NumeroCelular = phoneNumber });
        }

        //
        // POST: /Manage/VerifyPhoneNumber
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifyPhoneNumber(VerifyPhoneNumberViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var id = Convert.ToInt32(User.Identity.GetUserId());

            var result = await UserManager.ChangePhoneNumberAsync(id, model.NumeroCelular, model.Code);
            if (result.Succeeded)
            {
                var user = await UserManager.FindByIdAsync(id);
                if (user != null)
                {
                    await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                }
                return RedirectToAction("Index", new { Message = ManageMessageId.AddPhoneSuccess });
            }
            // If we got this far, something failed, redisplay form
            ModelState.AddModelError("", "Código errado!");
            return View(model);
        }

        //
        // POST: /Manage/RemovePhoneNumber
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> RemovePhoneNumber()
        {
            var id = Convert.ToInt32(User.Identity.GetUserId());

            var result = await UserManager.SetPhoneNumberAsync(id, null);
            if (!result.Succeeded)
            {
                return RedirectToAction("Index", new { Message = ManageMessageId.Error });
            }
            var user = await UserManager.FindByIdAsync(id);
            if (user != null)
            {
                await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
            }
            return RedirectToAction("Index", new { Message = ManageMessageId.RemovePhoneSuccess });
        }

        //
        // GET: /Manage/ChangePassword
        public ActionResult ChangePassword()
        {
            ViewBag.EmailAuth = GetEmailAdress();

            return View();
        }

        //
        // POST: /Manage/ChangePassword
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var id = Convert.ToInt32(User.Identity.GetUserId());

            var result = await UserManager.ChangePasswordAsync(id, model.SenhaAtual, model.NovaSenha);
            if (result.Succeeded)
            {
                var user = await UserManager.FindByIdAsync(id);
                if (user != null)
                {
                    await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                }
                return RedirectToAction("Index", new { Message = ManageMessageId.ChangePasswordSuccess });
            }
            ViewBag.EmailAuth = GetEmailAdress();
            AddErrors(result);
            return View(model);
        }

        //
        // GET: /Manage/SetPassword
        public ActionResult SetPassword()
        {
            ViewBag.EmailAuth = GetEmailAdress();

            return View();
        }

        //
        // POST: /Manage/SetPassword
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> SetPassword(SetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var id = Convert.ToInt32(User.Identity.GetUserId());

                var result = await UserManager.AddPasswordAsync(id, model.NovaSenha);
                if (result.Succeeded)
                {
                    var user = await UserManager.FindByIdAsync(id);
                    if (user != null)
                    {
                        await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                    }
                    return RedirectToAction("Index", new { Message = ManageMessageId.SetPasswordSuccess });
                }
                AddErrors(result);
            }

            ViewBag.EmailAuth = GetEmailAdress();

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Manage/ManageLogins
        public async Task<ActionResult> ManageLogins(ManageMessageId? message)
        {
            ViewBag.StatusMessage =
                message == ManageMessageId.RemoveLoginSuccess ? "O login externo foi removido com sucesso!"
                : message == ManageMessageId.Error ? "Um error ocorreu!"
                : "";

            var id = Convert.ToInt32(User.Identity.GetUserId());

            var user = await UserManager.FindByIdAsync(id);
            if (user == null)
            {
                return View("Error");
            }
            var userLogins = await UserManager.GetLoginsAsync(id);
            var otherLogins = AuthenticationManager.GetExternalAuthenticationTypes().Where(auth => userLogins.All(ul => auth.AuthenticationType != ul.LoginProvider)).ToList();

            ViewBag.ShowRemoveButton = user.PasswordHash != null || userLogins.Count > 1;
            ViewBag.EmailAuth = user.Email;

            return View(new ManageLoginsViewModel
            {
                CurrentLogins = userLogins,
                OtherLogins = otherLogins
            });
        }

        //
        // POST: /Manage/LinkLogin
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LinkLogin(string provider)
        {
            // Request a redirect to the external login provider to link a login for the current user
            return new ChallengeResult(provider, Url.Action("LinkLoginCallback", "Manage"), User.Identity.GetUserId());
        }

        //
        // GET: /Manage/LinkLoginCallback
        public async Task<ActionResult> LinkLoginCallback()
        {
            var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync(XsrfKey, User.Identity.GetUserId());
            if (loginInfo == null)
            {
                return RedirectToAction("ManageLogins", new { Message = ManageMessageId.Error });
            }

            var id = Convert.ToInt32(User.Identity.GetUserId());

            var result = await UserManager.AddLoginAsync(id, loginInfo.Login);
            return result.Succeeded ? RedirectToAction("ManageLogins") : RedirectToAction("ManageLogins", new { Message = ManageMessageId.Error });
        }

        #region Helpers

        private bool HasPassword()
        {
            var user = UserManager.FindById(Convert.ToInt16(User.Identity.GetUserId()));
            if (user != null)
            {
                return user.PasswordHash != null;
            }
            return false;
        }

        private bool HasPhoneNumber()
        {
            var user = UserManager.FindById(Convert.ToInt32(User.Identity.GetUserId()));
            if (user != null)
            {
                return user.PhoneNumber != null;
            }
            return false;
        }

        public enum ManageMessageId
        {
            AddPhoneSuccess,
            ChangePasswordSuccess,
            SetTwoFactorSuccess,
            SetPasswordSuccess,
            RemoveLoginSuccess,
            RemovePhoneSuccess,
            Error
        }

        #endregion
    }
}