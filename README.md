#OWIN OAuth Providers

Provides a set of extra authentication providers for OWIN ([Project Katana](http://katanaproject.codeplex.com/)).  This project includes providers for:
- OAuth
  - Google+
  - Yahoo
  - LinkedIn
  - GitHub
  - Instagram
  - StackExchange
  - HealthGraph
  - Battle.net
- OpenID
  - Generic OpenID 2.0 provider
  - Steam

## Implementation Guides
For guides on how to implement these providers, please visit my blog, [Be a Big Rockstar](http://www.beabigrockstar.com).

## Installation
To use these providers you will need to install the ```Owin.Security.Providers``` NuGet package.

```
PM> Install-Package Owin.Security.Providers
```
## License

The MIT License (MIT)

Copyright (c) 2014 Jerrie Pelser

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
