namespace Owin.Security.Providers.Shopify
{
    using System.Threading.Tasks;

    /// <summary>
    /// Specifies callback methods which the <see cref="ShopifyAuthenticationMiddleware"/> invokes to enable developer control over the authentication process.
    /// </summary>
    public interface IShopifyAuthenticationProvider
    {
        /// <summary>
        /// Invoked whenever Shopify shop successfully authenticates a user.
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the shop <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task Authenticated(ShopifyAuthenticatedContext context);

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        /// <param name="context">Instance of return endpoint context.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task ReturnEndpoint(ShopifyReturnEndpointContext context);
    }
}