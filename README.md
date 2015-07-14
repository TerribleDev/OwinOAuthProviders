[![Build status](https://ci.appveyor.com/api/projects/status/su8q95onnarswjaq/branch/master?svg=true)](https://ci.appveyor.com/project/ByteBlast/owinoauthproviders/branch/master)


#OWIN OAuth Providers

Provides a set of extra authentication providers for OWIN ([Project Katana](http://katanaproject.codeplex.com/)).  This project includes providers for:
- OAuth
  - ArcGISOnline
  - Asana
  - Battle.net
  - Buffer
  - DeviantArt
  - Dropbox
  - EVEOnline
  - Flickr
  - Foursquare
  - GitHub
  - Gitter
  - Google+
  - HealthGraph
  - Instagram
  - LinkedIn
  - PayPal
  - Reddit
  - Salesforce
  - Slack
  - SoundCloud
  - Spotify
  - StackExchange
  - Strava
  - TripIt
  - Twitch.tv
  - Untappd
  - Visual Studio Online
  - Wordpress
  - Yahoo
  - Yammer
- OpenID
  - Generic OpenID 2.0 provider
  - Steam
  - Wargaming

## Implementation Guides
For guides on how to implement these providers, please visit my blog, [Be a Big Rockstar](http://www.beabigrockstar.com).

## Installation
To use these providers you will need to install the ```Owin.Security.Providers``` NuGet package.

```
PM> Install-Package Owin.Security.Providers
```

## OwinOAuthProvidersDemo Project Setup - Git Ignore OwinOAuthProviderConfig
The OwinOAuthProvidersDemo project demonstrates how to use the OwinOAuthProviders, specifically the new Strava provider. The demo project uses **OwinOAuthProviderConfig.cs** struct to keep your client_id and client_secret keys out of version control system to prevent leaking authentication information.  Obviously this is not totally secure, as you will be able to see this in an decompiler but will keep it from version control.  Another option is to leverage Web.config transforms, added your keys to Web.Debug.config or Web.Release.config.  The initial version of the file provides an example how to setup a client_id and client_secret for Strava and LinkedIn.  Once you tell git to not track local changes to this file, you can update the struct with your secret information without fear of committing to the public.  Follow the steps outlined below to ensire git will ignore local changes for *OwinOAuthProviderConfig.cs*

```csharp
 public struct OwinOAuthProviderConfig
    {
        public struct Strava
        {
            public const string ClientId = "<ADD-CUSTOM-CLIENT-ID>";
            public const string ClientSecret = "<ADD-CUSTOM-CLIENT-SECRET>";
        }

        public struct LinkedIn
        {
            public const string ClientId = "<ADD-CUSTOM-CLIENT-ID>";
            public const string ClientSecret = "<ADD-CUSTOM-CLIENT-SECRET>";
        }
    }
```

Git has the power to ignore local changes to tracked files, but it’s slightly clunkier than and completely inconsistent with the familiar .gitignore. You must use git update-index to tell git to ignore changes to the file:

```
$ git update-index --assume-unchanged OwinOAuthProvidersDemo/OwinOAuthProviderConfig.cs
```
Now your git status will be clean, and you will have no unwanted results when you run things like git add . and git commit -a. And when you or somebody upstream modifies OwinOAuthProviderConfig.cs, git will not ask you to resolve the conflict.

To un-mark the file as assume-unchanged:

```
$ git update-index --no-assume-unchanged OwinOAuthProvidersDemo/OwinOAuthProviderConfig.cs
```
And if you want a list of tracked files that git is ignoring:

```
$ git ls-files -v | grep ^[a-z]
```

### Using OwinOAuthProviderConfig Struct in Startup
To tell OWIN to use Strava provider you need to configure the ASP.NET 5 Startup class ConfigureAuth method.  Tell the Applicaiton Builder to use the Strava Authentication with the **UseStravaApplicaiton** extension method passing in the clientId and clientSecret parameters.

```csharp
public partial class Startup
    {
        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            // Enable the application to use a cookie to store information for the signed in user
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login")
            });
            // Use a cookie to temporarily store information about a user logging in with a third party login provider
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            //http://localhost/OwinOAuthProvidersDemo/login/token
            app.UseStravaAuthentication(
                clientId: OwinOAuthProviderConfig.Strava.ClientId,
                clientSecret: OwinOAuthProviderConfig.Strava.ClientSecret
            );
        }
    }
```

## Contributions

If you would like to also contribute then please fork the repo, make your changes and submit a pull request.

A big thanks goes out to all these contributors without whom this would not have been possible.:
* Jérémie Bertrand (https://github.com/laedit)
* genuinebasil (https://github.com/genuinebasil)
* Tomáš Herceg (https://github.com/tomasherceg)
* Roberto Hernandez (https://github.com/rjhernandez)
* nbelyh (https://github.com/nbelyh)
* James Cuthbert (https://github.com/jokcofbut)
* ravind (https://github.com/ravind)
* Dave Timmins (https://github.com/davetimmins)
* Paul Cook (https://github.com/Simcon)
* Kristoffer Pettersson (https://github.com/KetaSwe)
* Joseph Yanks (https://github.com/josephyanks)
* Aaron Horst (https://github.com/aaron-horst)
* Scott Hill (https://github.com/scottedwardhill)
* Anthony Ruffino (https://github.com/AnthonyRuffino)
* Tommy Parnell (https://github.com/tparnell8)
* Maxime Roussin-Bélanger (https://github.com/Lorac)

For most accurate and up to date list of contributors please see https://github.com/RockstarLabs/OwinOAuthProviders/graphs/contributors

## License

The MIT License (MIT)

Copyright (c) 2014, 2015 Jerrie Pelser

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
