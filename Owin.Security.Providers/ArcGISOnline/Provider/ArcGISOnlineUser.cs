using System;

namespace Owin.Security.Providers.ArcGISOnline.Provider
{
    public class ArcGISOnlineUser
    {
        public User user { get; set; }
    }

    public class User
    {
        public string username { get; set; }
        public string fullName { get; set; }
        public string email { get; set; }
    }
}
