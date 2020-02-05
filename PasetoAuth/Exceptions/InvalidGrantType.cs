using System;

namespace PasetoAuth.Exceptions
{
    public class InvalidGrantType : Exception
    {
        public InvalidGrantType() : base("This grant type is unsupported")
        {
            
        }
    }
}