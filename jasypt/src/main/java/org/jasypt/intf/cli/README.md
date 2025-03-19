Readme for JasyptPBEFileDecryptionCLI

Run the JasyptPBEFileDecryptionCLI main method to achieve the results shared below.

-> Works as a utility for 1-click encryption/decryption of jasypt secrets for all environments of a service/services of a namespace.
Pre-requisites:
1. This utility will **NOT** work if:  
   (a) Services has hardcoded jasypt properties in code rather than in application.yml/mykaarma-config  
   (b) Service doesn't declare jasypt properties at all (using defaults of jasypt plugin)  
   (c) Currently, only the properties with below keys are handled in code (others can be similarly handled):  
   ```
   jasypt.encryptor.password  //from deployment.yml only
   jasypt.encryptor.algorithm
   jasypt.encryptor.key-obtention-iterations
   jasypt.encryptor.pool-size
   jasypt.encryptor.provider-name
   jasypt.encryptor.salt-generator-classname
   jasypt.encryptor.iv-generator-classname
   jasypt.encryptor.string-output-type
   ```
   
   Note: properties provided without dot-notation will also work, like:
   ```
   jasypt:
      encryptor:
         algorithm: ...
         key-obtention-iterations: ...
         pool-size: ...
         ...
   ```

2. Needs the **_latest code of the following repos to be cloned on local_**:  
**internal-systems** (for fetching jasypt pwd QA and prod)  
**vishwakarma** (for fetching jasypt pwd devvm)  
**mykaarma-config** (if the services use this)/repo(s) of the service(s) (if the services have local appllcation.yml resource) - to fetch the jasypt encryptor propertoes


The utility will perform the following:
1. Receive a namespace/service name as input.
2. For all services of that namespace/for that particular service, fetch the existing jasypt passwords for all environments (dev/qa/qa-canary/prod/prod-canary) from internal-systems and vishwakarma. Also, fetch the existing jasypt properties (like encryptor algo/provider/salt/IV generator etc) from the mykaarma-config file for each env for that service.
3. Decrypt in place all of the mykaarma-config files for above service(s) using a single command.

At this point, users will:  
(i) update the decrypted secrets/token/credentials with the rotated values in the service(s) config files, and   
(ii) set new jasypt pwds in their local internal-systems/vishwakarma repos.

After this, the same utility can now be used for re-encrypting these updated secrets in a single command using the new jasypt passwords.

Another useful ability this utility provides during encryption, is the ability to **create a random encryptor password per environment for each service** in code, which it uses for encrypting the keys for that service and then updates the same in deployment.yml file(s) as well.  


### ARGUMENTS

(Provided as static variables in the file)
```
static String namespace = "transportation";
static String specificServiceName = "";
static boolean printUselessLogs = false;
static boolean encrypt = false;
static boolean shouldGenerateNewPassword = true;
static int pwdLength = 20;
```

`namespace` - the namespace for which to run  
`specificServiceName` - a specific service in the namespace for which to run. If null/blank, runs for all services in the namespace  
`encrypt` - if true, runs encryption, else runs decryption  
`shouldGenerateNewPassword` - if true and if `encrypt` is also true, generates a new random password of length `pwdLength` for each environment of each service for which this is run, encrypts keys according to these new passwords and updates the passwords in deployment.yml in vishwakarma and internal-systems (QA+Prod)
