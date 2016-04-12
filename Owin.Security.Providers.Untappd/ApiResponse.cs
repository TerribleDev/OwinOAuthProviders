namespace Owin.Security.Providers.Untappd
{

    internal class ResponseRoot
    {
        public Meta Meta { get; set; }
        public Response Response { get; set; }
    }

    public class Meta
    {
        public int HTTPCode { get; set; }
    }

    public class Response
    {
        public string AccessToken { get; set; }
    }

}
