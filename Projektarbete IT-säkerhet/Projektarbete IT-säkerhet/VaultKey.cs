using System;
using System.Text;
using System.Security.Cryptography;

namespace Projektarbete_IT_säkerhet
{
    class VaultKey
    {
        public byte[] SecretKey;
        public byte[] Key;

        public VaultKey(string masterPwd)
        {
            SecretKey = GenerateSalt();
            Key = GenerateVaultKey(masterPwd, SecretKey);
        }

        public byte[] GenerateVaultKey(string password, byte[] SecretKey)
        {
            var pbkdf2 = new Rfc2898DeriveBytes(password, SecretKey);
            byte[] hash = pbkdf2.GetBytes(24);

            return hash;
        }

        public byte[] GenerateSalt()
        {
            var salt = new byte[24];
            new RNGCryptoServiceProvider().GetBytes(salt);

            return salt;
        }
    }
}
