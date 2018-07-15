using System;
using System.Configuration;
using System.Net;
using System.Net.Mail;
using System.Net.Mime;
using Microsoft.AspNet.Identity;
using System.Threading.Tasks;
using System.Web;

namespace MVCIdentity.Identity.Config
{
    public class EmailService : IIdentityMessageService
    {
        public Task SendAsync(IdentityMessage message)
        {
            // Plug in your email service here to send an email.
            return SendMail(message);
        }

        private Task SendMail(IdentityMessage message)
        {
            var contaEmail = ConfigurationManager.AppSettings["ContaEmail"];
            var senhaEmail = ConfigurationManager.AppSettings["SenhaEmail"];

            if (string.IsNullOrWhiteSpace(contaEmail))
            {
                throw new NullReferenceException("ContaEmail está vazio ou nulo!");
            }

            if (string.IsNullOrWhiteSpace(senhaEmail))
            {
                throw new NullReferenceException("SenhaEmail está vazio ou nulo!");
            }

            var text = HttpUtility.HtmlEncode(message.Body);

            var msg = new MailMessage();
            msg.From = new MailAddress("admin@portal.com.br", "Teste envio de email!");
            msg.To.Add(new MailAddress(message.Destination));
            msg.Subject = message.Subject;
            msg.AlternateViews.Add(AlternateView.CreateAlternateViewFromString(text, null, MediaTypeNames.Text.Plain));
            msg.AlternateViews.Add(AlternateView.CreateAlternateViewFromString(text, null, MediaTypeNames.Text.Html));

            var smtpClient = new SmtpClient("smtp.gmail.com", Convert.ToInt32(587));
            var credentials = new NetworkCredential(contaEmail, senhaEmail);
            smtpClient.Credentials = credentials;
            smtpClient.EnableSsl = true;
            smtpClient.Send(msg);


            return Task.FromResult(0);
        }
    }
}
