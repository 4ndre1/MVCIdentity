﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity.EntityFramework;
using MVCIdentity.Identity.Context.Models;

namespace MVCIdentity.Identity.Context.Stores
{
    public class UserStore : UserStore<User, Role, int, UserLogin, UserRole, UserClaim>
    {
        public UserStore(ApplicationDbContext context)
            : base(context)
        {
        }
    }
}
