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

            var client = new KeyClient(vaultUri: new Uri("https://wickedvault.vault.azure.net/"), credential: new DefaultAzureCredential());
        
            var key = client.GetKey("masterKey"); 
            System.Console.WriteLine(key.Value.Name);
            System.Console.WriteLine(key.Value.KeyMaterial.KeyType);

            string value = "testing";

            var encodedText = Encrypt(key, value);
            Decrypt(encodedText).GetAwaiter().GetResult();
        }

        private static async Task<string> Decrypt(string encryptedText) 
        {       
            var encryptedBytes = Convert.FromBase64String(encryptedText);
            System.Console.WriteLine("Decypting text");
            System.Console.WriteLine(encryptedBytes);
    
    	// var clientCredential = new ClientCredential("5314007c-a783-4b92-b713-e928214947e9", "0f76365a-7abc-40c5-b8f1-05e6964dae6c");
        // var kvc = new KeyVaultCredential(GetAccessTokenAsync);
    
            //GetKeyContent("https://wickedvault.vault.azure.net/");

            //var kv = GetKeyVaultClient(GetKeyVaultCallback());
        

            // var azureServiceTokenProvider = new AzureServiceTokenProvider();

            ///var kv = new KeyVaultClient(kvc, GetHttpClient());
            //var sc = kv.GetSecretAsync("https://wickedvault.vault.azure.net/", "masterKey");
            

            AuthenticationCallback callback = async (authority,resource,scope) =>
            {
                var appId = "5314007c-a783-4b92-b713-e928214947e9";
                var appSecret = "0f76365a-7abc-40c5-b8f1-05e6964dae6c";

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

            var result = client.GetSecretAsync("https://wickedvault.vault.azure.net", "test");   

            Console.WriteLine(result.Id);
            Console.WriteLine(client.ApiVersion);

            var decryptionResult = await client.DecryptAsync("masterKey",  JsonWebKeyEncryptionAlgorithm.RSAOAEP, encryptedBytes);

             var decryptedText = Encoding.Unicode.GetString(decryptionResult.Result);

            return decryptedText;

        }         


        private static HttpClient GetHttpClient()
        {
            var http = new HttpClient();
            //http.BaseAddress = new Uri("https://wickedvault.vault.azure.net");
            return http;
        }       

        private static async Task<string> GetAccessTokenAsync(string authority, string resource, string scope)
        {
            System.Console.WriteLine(authority);
            System.Console.WriteLine(resource);
            System.Console.WriteLine(scope);

            var context = new AuthenticationContext(authority, TokenCache.DefaultShared);
            var result = await context.AcquireTokenAsync(resource, clientCred);
            Console.WriteLine(scope);
            return result.AccessToken;
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

        private static AzureServiceTokenProvider.TokenCallback GetKeyVaultCallback()
        {
            AzureServiceTokenProvider azureServiceTokenProvider = new AzureServiceTokenProvider();
            return azureServiceTokenProvider.KeyVaultTokenCallback;
        }

        private static KeyVaultClient GetKeyVaultClient(AzureServiceTokenProvider.TokenCallback callback)
        {
            KeyVaultClient.AuthenticationCallback authCallback = new KeyVaultClient.AuthenticationCallback(callback);
            return new KeyVaultClient(authCallback);
        }

        public static string GetKeyContent(string keyIdentifier)
        {
            var kv = GetKeyVaultClient(GetKeyVaultCallback());
            var key = kv.GetKeyAsync(keyIdentifier);
            return key.Result.Key.ToString();
        }

    }
}
