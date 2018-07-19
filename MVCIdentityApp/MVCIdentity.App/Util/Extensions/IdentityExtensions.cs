using System;
using System.Data.Entity;
using System.Linq;
using System.Security.Principal;
using Microsoft.AspNet.Identity;
using MVCIdentity.Identity.Context;

namespace MVCIdentity.App.Util.Extensions
{
    public static class IdentityExtensions
    {
        public static string GetEmailAdress(this IIdentity identity, ApplicationDbContext context)
        {
            var userId = Convert.ToInt32(identity.GetUserId());
            var user = context.Users.FirstOrDefault(u => u.Id == userId);
            return user.Email;
        }
    }
}