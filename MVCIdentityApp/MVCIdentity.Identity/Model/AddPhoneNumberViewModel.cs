using System.ComponentModel.DataAnnotations;

namespace MVCIdentity.Identity.Model
{
    public class AddPhoneNumberViewModel
    {
        [Required]
        [Phone]
        [Display(Name = "Número de celular")]
        public string NumeroCelular { get; set; }
    }
}
