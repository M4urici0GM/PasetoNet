using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Serialization;
using FluentValidation;
using FluentValidation.Results;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Paseto.Builder;
using Paseto.Cryptography;
using Paseto.Protocol;
using PasetoAuth.Exceptions;
using PasetoAuth.Interfaces;
using PasetoAuth.Options;
using PasetoAuth.Validators;

namespace PasetoAuth.Common
{
    public class PasetoTokenHandler : IPasetoTokenHandler
    {
        private readonly IAuthenticationSchemeProvider _authenticationSchemeProvider;
        private readonly PasetoValidationParameters _validationParameters;
        
        public PasetoTokenHandler(IAuthenticationSchemeProvider authenticationSchemeProvider, PasetoValidationParameters validationParameters)
        {
            _authenticationSchemeProvider = authenticationSchemeProvider;
            _validationParameters = validationParameters;
        }
        
        public Task<string> WriteTokenAsync(PasetoTokenDescriptor descriptor) 
        {
            ValidationResult validationResult =  new TokenDescriptorValidator()
                .Validate(descriptor);
            if (!validationResult.IsValid)
                throw new ValidationException(validationResult.Errors);
            PasetoBuilder<Version2> pasetoBuilder = new PasetoBuilder<Version2>()
                .WithKey(GenerateKeyPairAsync(_validationParameters.SecretKey).Result.privateKey)
                .AsPublic()
                .AddClaim(RegisteredClaims.Audience, descriptor.Audience)
                .AddClaim(RegisteredClaims.Issuer, descriptor.Issuer)
                .AddClaim(PasetoRegisteredClaimsNames.IssuedAt, DateTime.Now)
                .Expiration(descriptor.Expires);
            if (!descriptor.NotBefore.Equals(null))
                pasetoBuilder.AddClaim(RegisteredClaims.NotBefore, descriptor.NotBefore);
            foreach (Claim claim in descriptor.Subject.Claims)
                pasetoBuilder.AddClaim(claim.Type, claim.Value);
            return Task.FromResult(pasetoBuilder.Build());
        }

        public Task<(byte[] publicKey, byte[] privateKey)> GenerateKeyPairAsync(string secretKey)
        {
            Ed25519.KeyPairFromSeed(out var publicKey, out var privateKey, 
                Encoding.ASCII.GetBytes(secretKey));
            return Task.FromResult((publicKey, privateKey));
        }

        public async Task<ClaimsPrincipal> DecodeTokenAsync(string token)
        {
            string decodedToken = new PasetoBuilder<Version2>()
                    .AsPublic()
                    .WithKey(GenerateKeyPairAsync(_validationParameters.SecretKey).Result.publicKey)
                    .Decode(token);
                
                JObject deserializedObject =  JObject.Parse(decodedToken);
                if (Convert.ToDateTime(deserializedObject["exp"]).CompareTo(DateTime.Now) < 0 || Convert.ToDateTime(deserializedObject["nbf"]).CompareTo(DateTime.Now) > 0)
                    throw new ExpiredToken();
                
                List<Claim> claimsList = new List<Claim>();

                await Task.Run(() =>
                {
                    foreach (var obj in deserializedObject.Properties())
                    {
                        switch (obj.Name)
                        {
                            case PasetoRegisteredClaimsNames.ExpirationTime:
                                claimsList.Add(new Claim(PasetoRegisteredClaimsNames.ExpirationTime,
                                    obj.Value.ToString()));
                                break;
                            case PasetoRegisteredClaimsNames.Audience:
                                claimsList.Add(new Claim(PasetoRegisteredClaimsNames.Audience, obj.Value.ToString()));
                                break;
                            case PasetoRegisteredClaimsNames.Issuer:
                                claimsList.Add(new Claim(PasetoRegisteredClaimsNames.Issuer, obj.Value.ToString()));
                                break;
                            case PasetoRegisteredClaimsNames.IssuedAt:
                                claimsList.Add(new Claim(PasetoRegisteredClaimsNames.IssuedAt, obj.Value.ToString()));
                                break;
                            case PasetoRegisteredClaimsNames.NotBefore:
                                claimsList.Add(new Claim(PasetoRegisteredClaimsNames.NotBefore, obj.Value.ToString()));
                                break;
                            case PasetoRegisteredClaimsNames.TokenIdentifier:
                                claimsList.Add(new Claim(PasetoRegisteredClaimsNames.TokenIdentifier,
                                    obj.Value.ToString()));
                                break;
                            default:
                                claimsList.Add(new Claim(obj.Name, obj.Value.ToString()));
                                break;
                        }
                    }
                });

                AuthenticationScheme authenticationScheme =
                    await _authenticationSchemeProvider.GetDefaultAuthenticateSchemeAsync();
                
                ClaimsIdentity identity = new ClaimsIdentity(claimsList, authenticationScheme.Name);
                return new ClaimsPrincipal(identity);
        }
    }
}