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
		public FoursquareAuthenticatedContext(IOwinContext context, JObject user, string accessToken) : base(context)
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
		public string AccessToken { get; private set; }
		public string Id { get; private set; }
		public string FirstName { get; private set; }
		public string LastName { get; private set; }
		public string Name { get; private set; }
		public string Gender { get; private set; }
		public string Photo { get; private set; }
		public string Friends { get; private set; }
		public string HomeCity { get; private set; }
		public string Bio { get; private set; }
		public string Contact { get; private set; }
		public string Phone { get; private set; }
		public string Email { get; private set; }
		public string Twitter { get; private set; }
		public string Facebook { get; private set; }
		public string Badges { get; private set; }
		public string Mayorships { get; private set; }
		public string Checkins { get; private set; }
		public string Photos { get; private set; }
		public string Scores { get; private set; }
		public string Link { get; private set; }
		public ClaimsIdentity Identity { get; set; }
		public AuthenticationProperties Properties { get; set; }

		private static string TryGetValue(JObject user, string propertyName)
		{
			JToken value;
			return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
		}
	}
}