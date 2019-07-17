# vaultazure

Illustrate how to work with azure vault 
- key 
- secret 
- certificates


Create your service principal using the following command :- 

az ad sp create-for-rbac -n "wickedapp2" --skip-assignment

Set the environment variables 

export AZURE_CLIENT_ID=
export AZURE_CLIENT_SECRET=
export AZURE_TENANT_ID=

If you encountered the following error message, 


Unhandled Exception: Microsoft.Azure.KeyVault.Models.KeyVaultErrorException: Operation returned an invalid status code 'BadRequest'


Check to ensure you have granted access for your MSI in keyvault access policy. 
For my case the problem is due to, specifying foAEP to false, instead of true.
var encryptedText = rsa.Encrypt(byteData, fOAEP: true); // use to be false, which BREAKS it! 






