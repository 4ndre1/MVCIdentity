using System.ComponentModel.DataAnnotations;

namespace MVCIdentity.Identity.Model
{
    public class VerifyPhoneNumberViewModel
    {
        [Required]
        [Display(Name = "Code")]
        public string Code { get; set; }

        [Required]
        [Phone]
        [Display(Name = "Número celular")]
        public string NumeroCelular { get; set; }
    }
}
