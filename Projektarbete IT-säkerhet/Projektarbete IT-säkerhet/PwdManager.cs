using System;
using System.IO;

using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;

namespace Projektarbete_IT_säkerhet
{
    class PwdManager
    {
        public void run()
        {
            Console.WriteLine("init: Create new vault.");
            Console.WriteLine("login: Log in to existing vault.");
            Console.WriteLine("get: Show stored values for some property or list properties in vault.");
            Console.WriteLine("set: Store value for some (possibly) property in vault.");
            Console.WriteLine("drop: Drop some property from vault.");
            Console.WriteLine("secret: Show secret key.");

            String command = Console.ReadLine();
            String[] commandsplit = command.Split(' ');

            if (commandsplit[0] == "init")
            {
                Console.WriteLine("Password:");
                String masterPwd = Console.ReadLine();

                VaultKey valvnyckel = new VaultKey(masterPwd);
                File.WriteAllText(commandsplit[1], JsonSerializer.Serialize(valvnyckel.SecretKey));

                Vault valv = new Vault();

                using(Aes myaes = Aes.Create())
                {
                    myaes.Key = valvnyckel.Key;

                    File.WriteAllText(commandsplit[2], JsonSerializer.Serialize(Encrypt(valv.Pwds, myaes.Key, myaes.IV)));
                    File.AppendAllText(commandsplit[2], JsonSerializer.Serialize(myaes.IV));
                }
            }

        }
        public byte[] Encrypt(Dictionary<String, String> pwdvault, byte[] key, byte[] IV)
        {
            byte[] encrypted;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = IV;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(pwdvault);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            return encrypted;
        }
        public string Decrypt(byte[] ciphertext, byte[] key, byte[] IV)
        {
            string plaintext = null;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = IV;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(ciphertext))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plaintext;
        }
    }
}
