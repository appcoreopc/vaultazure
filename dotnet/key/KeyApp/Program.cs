using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Microsoft.Azure.KeyVault;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Azure;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Azure.KeyVault.WebKey;

namespace KeyApp
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");

            var client = new KeyClient(vaultUri: new Uri("https://wickedvault.vault.azure.net/"), credential: new DefaultAzureCredential());

        
            var key = client.GetKey("masterKey");            
                        
            System.Console.WriteLine(key.Value.Name);

            System.Console.WriteLine(key.Value.KeyMaterial.KeyType);

            string value = "testing";

            var encodedText = Encrypt(key, value);

            Decrypt(key, encodedText).GetAwaiter().GetResult();

        }

        private async static Task<string> GetToken(string authority, string resource, string scope)
        {
            var authContext = new AuthenticationContext(authority);
            ClientCredential clientCred = new ClientCredential(
                "5314007c-a783-4b92-b713-e928214947e9",
                "0f76365a-7abc-40c5-b8f1-05e6964dae6c");
            AuthenticationResult result = await authContext.AcquireTokenAsync(resource, clientCred);

            if (result == null)
                throw new InvalidOperationException("Failed to obtain the JWT token");

            return result.AccessToken;
        }


        private static async Task<string> Decrypt(Azure.Response<Key> key, string encryptedText) 
        {                  

            var encryptedBytes = Convert.FromBase64String(encryptedText);

                       var azureServiceTokenProvider = new AzureServiceTokenProvider();
                       var keyVaultClient = new KeyVaultClient(
                           new KeyVaultClient.AuthenticationCallback(
                               azureServiceTokenProvider.KeyVaultTokenCallback));
                     //  builder.AddAzureKeyVault(
                     //      keyVaultEndpoint, keyVaultClient, new DefaultKeyVaultSecretManager());

            
            var decryptionResult = await keyVaultClient.EncryptAsync("masterKey",  JsonWebKeyEncryptionAlgorithm.RSAOAEP, encryptedBytes);

             var decryptedText = Encoding.Unicode.GetString(decryptionResult.Result);

            return decryptedText;

        }                

        private static string Encrypt(Azure.Response<Key> key, string value) {

            using (var rsa = new RSACryptoServiceProvider())
            {          
                var parameters = new RSAParameters()
                {
                    Modulus = key.Value.KeyMaterial.N,
                    Exponent = key.Value.KeyMaterial.E
                };
            
                rsa.ImportParameters(parameters);
                var byteData = Encoding.Unicode.GetBytes(value);
                var encryptedText = rsa.Encrypt(byteData, fOAEP: false);

                var encodedText = Convert.ToBase64String(encryptedText);

                System.Console.WriteLine($"rsa encrypted text {encryptedText}");
                System.Console.WriteLine($"encoded text {encodedText}");

                return encodedText;            
            }                   

        }
    }
}



// {
//   "appId": "5314007c-a783-4b92-b713-e928214947e9",
//   "displayName": "wickedapp",
//   "name": "http://wickedapp",
//   "password": "0f76365a-7abc-40c5-b8f1-05e6964dae6c",
//   "tenant": "c7edfba3-a241-4b80-a92f-a311dc6cd2df"
// }
