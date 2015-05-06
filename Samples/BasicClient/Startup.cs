using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(BasicClient.Startup))]
namespace BasicClient
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
