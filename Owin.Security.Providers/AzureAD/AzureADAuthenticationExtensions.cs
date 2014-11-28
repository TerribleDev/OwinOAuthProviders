//  Copyright (c) Stefan Negritoiu
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//
//  Based on Katana Project distributed under same License 
//  Copyright (c) Microsoft Open Technologies, Inc.

using System;

namespace Owin.Security.Providers.AzureAD
{
    public static class AzureADAuthenticationExtensions
    {
        public static IAppBuilder UseAzureADAuthentication(this IAppBuilder app, AzureADAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(AzureADAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseAzureADAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseAzureADAuthentication(new AzureADAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}