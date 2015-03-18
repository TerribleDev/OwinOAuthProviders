using System;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Foursquare.Provider
{
	public class FoursquareAuthenticatedContext : BaseContext
	{
		public FoursquareAuthenticatedContext(IOwinContext context, JObject user, String accessToken) : base(context)
		{
			if (user == null)
			{
				throw new ArgumentNullException("user");
			}

			this.User = user;
			this.AccessToken = accessToken;

			var userId = this.User["id"];

			if (userId == null)
			{
				throw new ArgumentException("The user does not have an id.", "user");
			}

			this.Id = TryGetValue(user, "id");
			this.FirstName = TryGetValue(user, "firstName");
			this.LastName = TryGetValue(user, "lastName");
			this.Name = this.FirstName + " " + this.LastName;
			this.Gender = TryGetValue(user, "gender");
			this.Photo = TryGetValue(user, "photo");
			this.Friends = TryGetValue(user, "friends");
			this.HomeCity = TryGetValue(user, "homeCity");
			this.Bio = TryGetValue(user, "bio");
			this.Contact = TryGetValue(user, "contact");
			this.Phone = TryGetValue(JObject.Parse(this.Contact), "phone");
			this.Email = TryGetValue(JObject.Parse(this.Contact), "email");
			this.Twitter = TryGetValue(JObject.Parse(this.Contact), "twitter");
			this.Facebook = TryGetValue(JObject.Parse(this.Contact), "facebook");
			this.Badges = TryGetValue(user, "badges");
			this.Mayorships = TryGetValue(user, "mayorships");
			this.Checkins = TryGetValue(user, "checkins");
			this.Photos = TryGetValue(user, "photos");
			this.Scores = TryGetValue(user, "scores");
			this.Link = "https://foursquare.com/user/" + this.Id;
		}

		public JObject User { get; private set; }
		public String AccessToken { get; private set; }
		public String Id { get; private set; }
		public String FirstName { get; private set; }
		public String LastName { get; private set; }
		public String Name { get; private set; }
		public String Gender { get; private set; }
		public String Photo { get; private set; }
		public String Friends { get; private set; }
		public String HomeCity { get; private set; }
		public String Bio { get; private set; }
		public String Contact { get; private set; }
		public String Phone { get; private set; }
		public String Email { get; private set; }
		public String Twitter { get; private set; }
		public String Facebook { get; private set; }
		public String Badges { get; private set; }
		public String Mayorships { get; private set; }
		public String Checkins { get; private set; }
		public String Photos { get; private set; }
		public String Scores { get; private set; }
		public String Link { get; private set; }
		public ClaimsIdentity Identity { get; set; }
		public AuthenticationProperties Properties { get; set; }

		private static String TryGetValue(JObject user, String propertyName)
		{
			JToken value;
			return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
		}
	}
}