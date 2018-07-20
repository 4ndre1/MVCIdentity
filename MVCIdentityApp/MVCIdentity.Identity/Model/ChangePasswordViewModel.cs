using System.ComponentModel.DataAnnotations;

namespace MVCIdentity.Identity.Model
{
    public class ChangePasswordViewModel
    {
        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Senha atual")]
        public string SenhaAtual { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "A {0} deve ter pelo menos {2} caracteres.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Nova senha")]
        public string NovaSenha { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirmar nova senha")]
        [Compare("NovaSenha", ErrorMessage = "A nova senha e a confirmação de senha não estão iguais.")]
        public string ConfirmarNovaSenha { get; set; }
    }
}
