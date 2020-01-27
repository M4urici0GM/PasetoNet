using System;

namespace PasetoAuth.Exceptions
{
    public class ExpiredToken : Exception
    {
        public ExpiredToken(string message = "Token expired.") : base(message)
        {
            
        }
    }
}