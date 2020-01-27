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
using PasetoAuth.Exceptions;
using PasetoAuth.Interfaces;

namespace PasetoAuth
{
    public class PasetoAuthHandler : AuthenticationHandler<PasetoValidationParameters>
    {
        private const string AuthorizationHeaderName = "Authorization";
        private readonly IPasetoTokenHandler _pasetoTokenHandler;
        
        public PasetoAuthHandler(
            IOptionsMonitor<PasetoValidationParameters> options, 
            ILoggerFactory logger, UrlEncoder encoder,
            ISystemClock clock,
            IPasetoTokenHandler pasetoTokenHandler) 
            : base(options, logger, encoder, clock)
        {
            _pasetoTokenHandler = pasetoTokenHandler;
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
                var claimsPrincipal = await _pasetoTokenHandler.DecodeTokenAsync(headerValue.Parameter);
                return AuthenticateResult.Success(new AuthenticationTicket(claimsPrincipal, Scheme.Name));
            }
            catch (Exception ex)
            {
                Response.Headers["Error-Message"] = ex.Message;
                return AuthenticateResult.Fail(ex);
            }
        }
        
        
    }
}