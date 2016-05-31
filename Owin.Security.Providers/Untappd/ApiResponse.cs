using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Owin.Security.Providers.Untappd
{

    internal class ResponseRoot
    {
        public Meta meta { get; set; }
        public Response response { get; set; }
    }

    public class Meta
    {
        public int http_code { get; set; }
    }

    public class Response
    {
        public string access_token { get; set; }
    }

}
