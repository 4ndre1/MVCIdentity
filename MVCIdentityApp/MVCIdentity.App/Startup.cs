using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(MVCIdentity.App.Startup))]
namespace MVCIdentity.App
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
