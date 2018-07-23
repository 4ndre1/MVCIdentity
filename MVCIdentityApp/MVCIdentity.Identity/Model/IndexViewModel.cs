using Microsoft.AspNet.Identity;
using System.Collections.Generic;

namespace MVCIdentity.Identity.Model
{
    public class IndexViewModel
    {
        public bool TemSenha { get; set; }
        public IList<UserLoginInfo> Logins { get; set; }
        public string NumeroCelular { get; set; }
        public bool TwoFactor { get; set; }
        public bool BrowserRemembered { get; set; }
    }
}
