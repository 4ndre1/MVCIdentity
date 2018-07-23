using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace MVCIdentity.Identity.Model
{
    public class SendCodeViewModel
    {
        [Display(Name = "Tipo de envio")]
        public string ProviderSelecionado { get; set; }
        public ICollection<SelectListItem> Providers { get; set; }
        public string ReturnUrl { get; set; }
        public bool LembrarMe { get; set; }
    }
}
