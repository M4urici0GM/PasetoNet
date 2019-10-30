using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace PasetoAuth
{
    public static class PasetoAuthExtensions
    {
        public static AuthenticationBuilder AddPaseto(this AuthenticationBuilder builder)
        {
            throw new NotImplementedException();
        }

        public static AuthenticationBuilder AddPaseto(
            this AuthenticationBuilder builder,
            Action<PasetoOptions> configureOptions)
        {
            throw new NotImplementedException();
        }
        
        public static AuthenticationBuilder AddPaseto(
            this AuthenticationBuilder builder,
            string authenticationScheme,
            string displayName,
            Action<PasetoOptions> configureOptions)
        {
            throw new NotImplementedException();
        }
    }
}