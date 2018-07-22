using Microsoft.AspNet.Identity;
using System.Configuration;
using System.Threading.Tasks;
using Nexmo.Api;
using Nexmo.Api.Request;

namespace MVCIdentity.Identity.Config
{
    public class SmsService : IIdentityMessageService
    {
        public Task SendAsync(IdentityMessage identityMessage)
        {
            // Find your Account Sid and Auth Token at twilio.com/console
            string key = ConfigurationManager.AppSettings["NexmoKey"];
            string pass = ConfigurationManager.AppSettings["NexmoSecret"];

            var client = new Client(new Credentials
            {
                ApiKey = key,
                ApiSecret = pass
            });

            var results = client.SMS.Send(new SMS.SMSRequest()
            {
                from = "MVC Identity",
                to = identityMessage.Destination,
                text = identityMessage.Body
            });

            return Task.FromResult(0);
        }
    }
}
