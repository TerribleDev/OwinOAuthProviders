namespace Owin.Security.Providers.Shopify
{
    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Provider;
    using Newtonsoft.Json.Linq;
    using System.Security.Claims;

    public class ShopifyAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ShopifyAuthenticatedContext"/> class.
        /// </summary>
        /// <param name="context">The OWIN environment.</param>
        /// <param name="shop">The JSON-serialized shop.</param>
        /// <param name="accessToken">Shopify shop access token.</param>
        public ShopifyAuthenticatedContext(IOwinContext context, JObject shop, string accessToken)
            : base(context)
        {
            Shop = shop;
            AccessToken = accessToken;

            Id = TryGetValue(shop, "id");
            var fullShopifyDomainName = TryGetValue(shop, "myshopify_domain");
            UserName = string.IsNullOrWhiteSpace(fullShopifyDomainName) ? null : fullShopifyDomainName.Replace(".myshopify.com", "");
            Email = TryGetValue(shop, "email");
            ShopName = TryGetValue(shop, "name");
        }

        /// <summary>
        /// Gets the JSON-serialized Shopify shop.
        /// </summary>
        /// <remarks>Contains the Shopify shop information obtained from the Shop endpoint. By default this is https://{shopname}.myshopify.com/admin/shop but it can be overridden in the options.</remarks>
        public JObject Shop { get; private set; }

        /// <summary>
        /// Gets the Shopify shop access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Shopify shop Id.
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the Shopify shop domain name.
        /// </summary>
        /// <remarks>{shop_domain_name}.myshopify.com - without the ".myshopify.com" to be used as suggested username.</remarks>
        public string UserName { get; private set; }

        /// <summary>
        /// Gets the Shopify shop primary email address.
        /// </summary>
        public string Email { get; private set; }

        /// <summary>
        /// Gets the Shopify shop name.
        /// </summary>
        public string ShopName { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the Shopify shop.
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JToken shop, string propertyName)
        {
            var propertyValue = shop?.First?.First?[propertyName];
            return propertyValue?.ToString();
        }
    }
}