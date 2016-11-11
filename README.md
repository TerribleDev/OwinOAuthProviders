[![Build status](https://ci.appveyor.com/api/projects/status/gjlkpp86t8dw164f?svg=true)](https://ci.appveyor.com/project/tparnell8/owinoauthproviders)

#OWIN OAuth Providers

Provides a set of extra authentication providers for OWIN ([Project Katana](http://katanaproject.codeplex.com/)).  This project includes providers for:
- OAuth
  - ArcGISOnline
  - Asana
  - Backlog
  - Battle.net
  - Bitbucket
  - Buffer
  - Cosign
  - DeviantArt
  - Discord
  - Dropbox
  - EVEOnline
  - Fitbit
  - Flickr
  - Foursquare
  - Geni
  - GitHub
  - Gitter
  - Google+
  - HealthGraph
  - Instagram
  - LinkedIn
  - MyHeritage
  - Onshape
  - ORCID
  - PayPal
  - Reddit
  - Salesforce
  - Shopify
  - Slack
  - SoundCloud
  - Spotify
  - StackExchange
  - TripIt
  - Twitch.tv
  - Untappd
  - Vimeo
  - Visual Studio Online
  - VKontakte
  - Wordpress
  - Xing
  - Yahoo
  - Yammer
- OpenID
  - Generic OpenID 2.0 provider
  - Steam
  - Wargaming

## Implementation Guides
Take a look at the [samples project](https://github.com/TerribleDev/OwinOAuthProviders/blob/master/OwinOAuthProvidersDemo/App_Start/Startup.Auth.cs#L39). 



## Installation

You may install each provider via nuget separately. They are named Owin.Security.Providers.*, or you may install the meta package `Owin.Security.Providers` which will give you all 40+ providers.

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
* Jaspalsinh Chauhan (https://github.com/jsinh)
* Jason Loeffler (https://github.com/jmloeffler)
* Ben Foster (https://github.com/benfoster)
* Jonathan Peterson (https://github.com/eonasdan)

For most accurate and up to date list of contributors please see https://github.com/TerribleDev/OwinOAuthProviders/graphs/contributors

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
