namespace Owin.Security.Providers.Imgur.Provider
{
    using System;
    using System.Threading.Tasks;

    public class ImgurAuthenticationProvider : IImgurAuthenticationProvider
    {
        public Task Authenticated(ImgurAuthenticatedContext context)
        {
            throw new NotImplementedException();
        }

        public Task ReturnEndpoint(ImgurReturnEndpointContext context)
        {
            throw new NotImplementedException();
        }
    }
}
