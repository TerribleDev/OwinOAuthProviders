namespace Owin.Security.Providers.Imgur.Provider
{
    using System.Threading.Tasks;

    /// <summary></summary>
    public interface IImgurAuthenticationProvider
    {
        /// <summary></summary>
        /// <param name="context"></param>
        /// <returns></returns>
        Task Authenticated(ImgurAuthenticatedContext context);

        /// <summary></summary>
        /// <param name="context"></param>
        /// <returns></returns>
        Task ReturnEndpoint(ImgurReturnEndpointContext context);
    }
}
