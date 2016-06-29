namespace Owin.Security.Providers.Shopify
{
    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Provider;

    /// <summary>
    /// Provides context information to middleware providers.
    /// </summary>
    public class ShopifyReturnEndpointContext : ReturnEndpointContext
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ShopifyReturnEndpointContext"/> class.
        /// </summary>
        /// <param name="context">OWIN environment.</param>
        /// <param name="ticket">The authentication ticket.</param>
        public ShopifyReturnEndpointContext(IOwinContext context, AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }
    }
}