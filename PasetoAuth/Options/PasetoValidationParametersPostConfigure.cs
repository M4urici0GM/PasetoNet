using System;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Options;

namespace PasetoAuth.Options
{
    public class PasetoValidationParametersPostConfigure : IPostConfigureOptions<PasetoValidationParameters>
    {
        public void PostConfigure(string name, PasetoValidationParameters options)
        {
            if (string.IsNullOrEmpty(options.SecretKey))
                throw new InvalidOperationException("Secret key is required.");
            if (options.SecretKey.Length < 32 || options.SecretKey.Length > 32)
                throw new InvalidOperationException("Secret key must have 32 chars.");
        }
    }
}