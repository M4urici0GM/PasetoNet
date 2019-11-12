using System;
using System.Collections.Generic;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;
using Paseto.Builder;
using Paseto.Cryptography;
using Paseto.Protocol;
using PasetoAuth.Common;
using PasetoAuth.Options;
using System.Linq;

namespace PasetoAuth
{
    public class PasetoAuthHandler : AuthenticationHandler<PasetoValidationParameters>
    {
        private const string AuthorizationHeaderName = "Authorization";
        public PasetoAuthHandler(
            IOptionsMonitor<PasetoValidationParameters> options, 
            ILoggerFactory logger, UrlEncoder encoder,
            ISystemClock clock) 
            : base(options, logger, encoder, clock)
        {
        }

       
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {

            if (!Request.Headers.ContainsKey(AuthorizationHeaderName))
                return AuthenticateResult.NoResult();
            
            if (!AuthenticationHeaderValue.TryParse(Request.Headers[AuthorizationHeaderName], out AuthenticationHeaderValue headerValue))
                return AuthenticateResult.NoResult();
            
            if (!Scheme.Name.Equals(headerValue.Scheme, StringComparison.OrdinalIgnoreCase))
                return AuthenticateResult.NoResult();

            try
            {
                string decodedToken = new PasetoBuilder<Version2>()
                    .AsPublic()
                    .WithKey(PasetoDefaults.GenerateKeys(Options.SecretKey).publicKey)
                    .Decode(headerValue.Parameter);
                
                JObject deserializedObject =  JObject.Parse(decodedToken);
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
                
                ClaimsIdentity identity = new ClaimsIdentity(claimsList, Scheme.Name);
                ClaimsPrincipal principal = new ClaimsPrincipal(identity);
                return AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name));
            }
            catch (Exception ex)
            {
                Response.Headers["Error-Message"] = ex.Message;
                return AuthenticateResult.Fail(ex);
            }
        }
    }
}