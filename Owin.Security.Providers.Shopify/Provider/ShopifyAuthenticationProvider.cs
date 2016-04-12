namespace Owin.Security.Providers.Shopify
{
    using System;
    using System.Threading.Tasks;

    /// <summary>
    /// Default <see cref="IShopifyAuthenticationProvider"/> implementation.
    /// </summary>
    public class ShopifyAuthenticationProvider : IShopifyAuthenticationProvider
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ShopifyAuthenticationProvider"/> class.
        /// </summary>
        public ShopifyAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
        }

        /// <summary>
        /// Gets or sets the function that is invoked when the Authenticated method is invoked.
        /// </summary>
        public Func<ShopifyAuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        /// Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.
        /// </summary>
        public Func<ShopifyReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        /// <summary>
        /// Invoked whenever Shopify shop successfully authenticates a user.
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the shop <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task Authenticated(ShopifyAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        /// <param name="context">Instance of return endpoint context.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task ReturnEndpoint(ShopifyReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}