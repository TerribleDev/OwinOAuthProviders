using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(OwinOAuthProvidersDemo.Startup))]
namespace OwinOAuthProvidersDemo
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
