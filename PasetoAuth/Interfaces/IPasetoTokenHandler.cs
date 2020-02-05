using System.Security.Claims;
using System.Threading.Tasks;
using PasetoAuth.Common;

namespace PasetoAuth.Interfaces
{
    public interface IPasetoTokenHandler
    {
        Task<PasetoToken> WriteTokenAsync(PasetoTokenDescriptor tokenDescriptor);
        Task<ClaimsPrincipal> DecodeTokenAsync(string token);
        Task<(byte[] publicKey, byte[] privateKey)> GenerateKeyPairAsync(string secretKey);
    }
}