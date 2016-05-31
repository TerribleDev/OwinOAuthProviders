namespace Owin.Security.Providers.ArcGISOnline.Provider
{
    public class ArcGISOnlineUser
    {
        public User User { get; set; }
    }

    public class User
    {
        public string Username { get; set; }
        public string FullName { get; set; }
        public string Email { get; set; }
    }
}
