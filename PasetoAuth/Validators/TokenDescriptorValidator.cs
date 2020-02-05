using FluentValidation;
using PasetoAuth.Common;
using System.Linq;
namespace PasetoAuth.Validators
{
    public class TokenDescriptorValidator : AbstractValidator<PasetoTokenDescriptor>
    {
        public TokenDescriptorValidator()
        {
            RuleFor(t => t.Audience)
                .NotEmpty();
            RuleFor(t => t.Issuer)
                .NotEmpty();
            RuleFor(t => t.Expires)
                .NotEmpty();
            RuleFor(t => t.Subject)
                .NotEmpty();
        }
    }
}