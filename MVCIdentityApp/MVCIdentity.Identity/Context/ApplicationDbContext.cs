using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Data.Entity;

namespace MVCIdentity.Identity.Context
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>, IDisposable
    {
        public ApplicationDbContext()
            : base("Identity", throwIfV1Schema: false)
        {
        }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            //Troca o padrão dos nomes da tabela do identity!
            modelBuilder.Entity<ApplicationUser>().ToTable("Users");
            modelBuilder.Entity<IdentityUserRole>().ToTable("UserRoles");
            modelBuilder.Entity<IdentityUserLogin>().ToTable("UserLogins");
            modelBuilder.Entity<IdentityUserClaim>().ToTable("UserClaims");
            modelBuilder.Entity<IdentityRole>().ToTable("Roles");
        }

        public static ApplicationDbContext Create()
        {
            return new ApplicationDbContext();
        }

        /*
         * Command for Package Manager Console -> Migrations Entity Framework!
         * Enable-Migrations
         * Add-Migration 'NameMigrations'
         * Update-Database
         */
    }
}
