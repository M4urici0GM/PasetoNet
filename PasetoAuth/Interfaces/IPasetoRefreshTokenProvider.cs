using System.Security.Claims;
using System.Threading.Tasks;

namespace PasetoAuth.Interfaces
{
    public interface IPasetoRefreshTokenProvider
    {
        Task<ClaimsPrincipal> ReceiveAsync(string refreshToken);
        Task<string> CreateAsync(ClaimsPrincipal claimsPrincipal);
    }
}