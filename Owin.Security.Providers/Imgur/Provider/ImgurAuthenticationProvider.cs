namespace Owin.Security.Providers.Imgur.Provider
{
    using System;
    using System.Threading.Tasks;

    /// <summary></summary>
    public class ImgurAuthenticationProvider : IImgurAuthenticationProvider
    {
        /// <summary></summary>
        public ImgurAuthenticationProvider()
        {
            this.OnAuthenticated = context => Task.FromResult<object>(null);
            this.OnReturnEndpoint = context => Task.FromResult<object>(null);
        }

        /// <summary></summary>
        public Func<ImgurAuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary></summary>
        public Func<ImgurReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        /// <summary></summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public Task Authenticated(ImgurAuthenticatedContext context)
        {
            return this.OnAuthenticated(context);
        }

        /// <summary></summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public Task ReturnEndpoint(ImgurReturnEndpointContext context)
        {
            return this.OnReturnEndpoint(context);
        }
    }
}
