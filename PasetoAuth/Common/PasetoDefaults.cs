using System.Text;
using Paseto.Cryptography;

namespace PasetoAuth.Common
{
    public class PasetoDefaults
    {
        public const string Bearer = "Bearer";
        public static (byte[] privateKey, byte[] publicKey) GenerateKeys(string secretKey)
        {
            Ed25519.KeyPairFromSeed(out var publicKey, out var privateKey, 
                Encoding.ASCII.GetBytes(secretKey));
            return (privateKey, publicKey);
        }
    }
}