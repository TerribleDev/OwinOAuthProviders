namespace Owin.Security.Providers.Imgur.Provider
{
    using System;
    using System.Threading.Tasks;

    public class ImgurAuthenticationProvider : IImgurAuthenticationProvider
    {
        public ImgurAuthenticationProvider()
        {
            this.OnAuthenticated = context => Task.FromResult<object>(null);
            this.OnReturnEndpoint = context => Task.FromResult<object>(null);
        }

        public Func<ImgurAuthenticatedContext, Task> OnAuthenticated { get; set; }

        public Func<ImgurReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        public Task Authenticated(ImgurAuthenticatedContext context)
        {
            return this.OnAuthenticated(context);
        }

        public Task ReturnEndpoint(ImgurReturnEndpointContext context)
        {
            return this.OnReturnEndpoint(context);
        }
    }
}
