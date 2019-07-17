using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Microsoft.Azure.KeyVault;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Azure.KeyVault.WebKey;
using System.Net.Http;
using static Microsoft.Azure.KeyVault.KeyVaultClient;

namespace KeyApp
{
    class Program
    {
        static ClientCredential clientCred = null;

        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
          
            string value = "testing";
            var encodedText = Encrypt(value).GetAwaiter().GetResult();

            var result = Decrypt(encodedText).GetAwaiter().GetResult();
        }

        private static async Task<string> Decrypt(string encryptedText)
        {
            Console.WriteLine("Source value ################################");
            Console.WriteLine(encryptedText);
            Console.WriteLine("Source value ################################");

            var encryptedBytes = Convert.FromBase64String(encryptedText);
            System.Console.WriteLine("Decypting text");
            System.Console.WriteLine(encryptedBytes);
       

            AuthenticationCallback callback = async (authority, resource, scope) =>
            {
                var appId = "";
                var appSecret = "";
                //resource = "/subscriptions/0d2be596-245f-4f2e-8f16-abdc53bf0042/resourceGroups/rgkv/providers/Microsoft.KeyVault/vaults/wickedvault";

                System.Console.WriteLine($"Authority {authority}");
                System.Console.WriteLine($"resource {resource}");
                System.Console.WriteLine($"scope {scope}");

                var authContext = new AuthenticationContext(authority);

                var credential = new ClientCredential(appId, appSecret);
                var authResult = await authContext.AcquireTokenAsync(resource, credential);
                return authResult.AccessToken;
            };

            System.Console.WriteLine($"Setting up client");
            var client = new KeyVaultClient(callback);
    
            var decryptionResult = await client.DecryptAsync("https://wickedvault.vault.azure.net/keys/masterKey/4a43739e319941a889321e801d8534a4", JsonWebKeyEncryptionAlgorithm.RSAOAEP, encryptedBytes);

            var decryptedText = Encoding.Unicode.GetString(decryptionResult.Result);
            Console.WriteLine($"decrypted : {decryptedText}");
            return decryptedText;

        }

        private static async Task<string> Encrypt(string value)
        {
            AuthenticationCallback callback = async (authority, resource, scope) =>
            {
                var appId = "";
                var appSecret = "";

                System.Console.WriteLine($"Authority {authority}");
                System.Console.WriteLine($"resource {resource}");
                System.Console.WriteLine($"scope {scope}");

                var authContext = new AuthenticationContext(authority);

                var credential = new ClientCredential(appId, appSecret);
                var authResult = await authContext.AcquireTokenAsync(resource, credential);
                return authResult.AccessToken;
            };

            System.Console.WriteLine($"Setting up client");
            var client = new KeyVaultClient(callback);

            var key = await client.GetKeyAsync("https://wickedvault.vault.azure.net", "masterKey");


            using (var rsa = new RSACryptoServiceProvider())
            {
                var parameters = new RSAParameters()
                {
                    Modulus = key.Key.N,
                    Exponent = key.Key.E
                };

                rsa.ImportParameters(parameters);
                var byteData = Encoding.Unicode.GetBytes(value);
                var encryptedText = rsa.Encrypt(byteData, fOAEP: true);

                var encodedText = Convert.ToBase64String(encryptedText);

                System.Console.WriteLine($"rsa encrypted text {encryptedText}");
                System.Console.WriteLine($"encoded text {encodedText}");

                return encodedText;
            }
        }      
    }
}
