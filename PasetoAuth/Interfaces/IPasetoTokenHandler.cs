using System.Security.Claims;
using System.Threading.Tasks;
using PasetoAuth.Common;

namespace PasetoAuth.Interfaces
{
    public interface IPasetoTokenHandler
    {
        Task<string> WriteTokenAsync(PasetoTokenDescriptor tokenDescriptor);
        Task<ClaimsPrincipal> DecodeTokenAsync(string token);
        Task<(byte[] publicKey, byte[] privateKey)> GenerateKeyPairAsync(string secretKey);
    }
}