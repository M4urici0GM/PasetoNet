using System.Security.Claims;
using System.Threading.Tasks;
using System.Xml;
using FluentValidation;
using FluentValidation.Results;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Paseto.Builder;
using Paseto.Protocol;
using PasetoAuth.Validators;

namespace PasetoAuth.Common
{
    public class PasetoTokenHandler
    {
        public Task<string> WriteToken(PasetoTokenDescriptor descriptor) 
        {
            ValidationResult validationResult =  new TokenDescriptorValidator()
                .Validate(descriptor);
            if (!validationResult.IsValid)
                throw new ValidationException(validationResult.Errors);
            PasetoBuilder<Version2> pasetoBuilder = new PasetoBuilder<Version2>()
                .WithKey(PasetoDefaults.GenerateKeys(descriptor.SecretKey).privateKey)
                .AsPublic()
                .AddClaim(RegisteredClaims.Audience, descriptor.Audience)
                .AddClaim(RegisteredClaims.Issuer, descriptor.Issuer)
                .Expiration(descriptor.Expires);
            if (!descriptor.NotBefore.Equals(null))
                pasetoBuilder.AddClaim(RegisteredClaims.NotBefore, descriptor.NotBefore);
            foreach (Claim claim in descriptor.Subject.Claims)
            {
                pasetoBuilder.AddClaim(claim.Type, claim.Value);
            }
            return Task.FromResult(pasetoBuilder.Build());
        }
    }
}