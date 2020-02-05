using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;
using Paseto.Builder;
using Paseto.Cryptography;
using Paseto.Protocol;
using PasetoAuth.Exceptions;
using PasetoAuth.Interfaces;
using PasetoAuth.Options;

namespace PasetoAuth.Common
{
    public class PasetoTokenHandler : IPasetoTokenHandler
    {
        private readonly IAuthenticationSchemeProvider _authenticationSchemeProvider;
        private readonly PasetoValidationParameters _validationParameters;

        public PasetoTokenHandler(IAuthenticationSchemeProvider authenticationSchemeProvider,
            IOptions<PasetoValidationParameters> validationParameters)
        {
            _authenticationSchemeProvider = authenticationSchemeProvider;
            _validationParameters = validationParameters.Value;
        }

        public Task<PasetoToken> WriteTokenAsync(PasetoTokenDescriptor descriptor)
        {
            PasetoToken pasetoToken = new PasetoToken();
            DateTime now = DateTime.Now;
            DateTime expirationDate = descriptor.Expires ?? now.AddSeconds(_validationParameters.DefaultExpirationTime);
            string audience = descriptor.Audience ?? _validationParameters.Audience;
            string issuer = descriptor.Issuer ?? _validationParameters.Issuer;

            PasetoBuilder<Version2> pasetoBuilder = new PasetoBuilder<Version2>()
                .WithKey(GenerateKeyPairAsync(_validationParameters.SecretKey).Result.privateKey)
                .AsPublic()
                .AddClaim(RegisteredClaims.Audience, audience)
                .AddClaim(RegisteredClaims.Issuer, issuer)
                .AddClaim(PasetoRegisteredClaimsNames.IssuedAt, now)
                .Expiration(expirationDate);
            if (!descriptor.NotBefore.Equals(null))
                pasetoBuilder.AddClaim(RegisteredClaims.NotBefore, descriptor.NotBefore);
            foreach (Claim claim in descriptor.Subject.Claims)
                pasetoBuilder.AddClaim(claim.Type, claim.Value);
            
            pasetoToken.Token = pasetoBuilder.Build();
            pasetoToken.CreatedAt = now;
            pasetoToken.ExpiresAt = expirationDate;
            if (_validationParameters != null && _validationParameters.PasetoRefreshTokenProvider != null)
                pasetoToken.RefreshToken = _validationParameters.PasetoRefreshTokenProvider.CreateAsync(descriptor.Subject).Result;
            return Task.FromResult(pasetoToken);
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

            JObject deserializedObject = JObject.Parse(decodedToken);
            if (Convert.ToDateTime(deserializedObject["exp"]).CompareTo(DateTime.Now) < 0 ||
                Convert.ToDateTime(deserializedObject["nbf"]).CompareTo(DateTime.Now) > 0)
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