using System;
using Microsoft.AspNetCore.Authentication;
using PasetoAuth.Interfaces;

namespace PasetoAuth.Options
{
    public class PasetoValidationParameters : AuthenticationSchemeOptions
    {
        public string SecretKey { get; set; }
        public string Audience { get; set; }
        public string Issuer { get; set; }
        public DateTime? ClockSkew { get; set; }
        public bool? ValidateIssuer { get; set; } = true;
        public bool? ValidateAudience { get; set; } = true;
        public bool? UseRefreshToken { get; set; }
        public IPasetoRefreshTokenProvider PasetoRefreshTokenProvider { get; set; }
    }
}