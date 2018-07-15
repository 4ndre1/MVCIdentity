using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Data.Entity;
using MVCIdentity.Identity.Context.Models;

namespace MVCIdentity.Identity.Context
{
    public class ApplicationDbContext : IdentityDbContext<User, Role, int, UserLogin, UserRole, UserClaim>, IDisposable
    {
        public ApplicationDbContext()
            : base("Identity")
        {
        }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            //Troca o padrão dos nomes da tabela do identity!
            modelBuilder.Entity<User>().ToTable("Users");
            modelBuilder.Entity<UserRole>().ToTable("UserRoles");
            modelBuilder.Entity<UserLogin>().ToTable("UserLogins");
            modelBuilder.Entity<UserClaim>().ToTable("UserClaims");
            modelBuilder.Entity<Role>().ToTable("Roles");
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
