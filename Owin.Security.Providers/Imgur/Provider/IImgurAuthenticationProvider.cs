namespace Owin.Security.Providers.Imgur.Provider
{
    using System.Threading.Tasks;

    public interface IImgurAuthenticationProvider
    {
        Task Authenticated(ImgurAuthenticatedContext context);

        Task ReturnEndpoint(ImgurReturnEndpointContext context);
    }
}
