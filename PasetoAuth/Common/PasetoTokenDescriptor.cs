using System;
using System.Security.Claims;
using System.Security.Principal;

namespace PasetoAuth.Common
{
    public class PasetoTokenDescriptor
    {
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public ClaimsIdentity Subject { get; set; }
        public DateTime? NotBefore { get; set; }
        public DateTime? Expires { get; set; }
        
    }
}