Readme for JasyptPBEFileDecryptionCLI

Run the JasyptPBEFileDecryptionCLI main method to achieve the results shared below.

-> Works as a utility for 1-click encryption/decryption of jasypt secrets for all environments of a service/services of a namespace.

**Limitations:**
1. In case of application.yml, jasypt encryption configs (like `jasypt.encryptor.algorithm`, `jasypt.encryptor.salt-generator-classname`, etc) should **either be present in the 1st (common) section, or all properties must be overridden in the respective profile section**. If even a single jasypt encryptor related property is present in the environment specific section, this utility will ignore ALL jasypt encryptor related properties of the common section for that environment.   

**Pre-requisites:**
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


**Pre-run steps:**
1. Update TMP_FOLDER_PATH and GIT_REPO_PATH to point to your local system (GIT_REPO_PATH directory should have your required repos as stated in pre-requisites).
2. Add entries for your service in `serviceToMykaarmaConfigNameMap` or `serviceToApplicationYmlRelativePathMap` whichever applicable - key will be the name of service in kubernetes deployment file, value will be the name of service file in mykaarma-config/relative path of application.yml file to git folder (whichever applicable)



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
static String specificEnv = "";
static boolean printUselessLogs = false;
static boolean encrypt = false;
static boolean shouldGenerateNewPassword = true;
static int pwdLength = 20;
static String customMykaarmaConfigBasePath = "";
```

`namespace` - the namespace for which to run  
`specificServiceName` - a specific service in the namespace for which to run. If null/blank, runs for all services in the namespace
`specificEnv` - one of "prod","prod-canary","qa-aws","qa-aws-canary","devvm" - if you want to run for a specific env. Blank means run for all env
`encrypt` - if true, runs encryption, else runs decryption  
`shouldGenerateNewPassword` - if true and if `encrypt` is also true, generates a new random password of length `pwdLength` for each environment of each service for which this is run, encrypts keys according to these new passwords and updates the passwords in deployment.yml in vishwakarma and internal-systems (QA+Prod). **IMPORTANT NOTE: This only works if the passwords are different for each service in the same deployment.yml file (passwords can be common in different deployment.yml files). If this is your use-case, either set your passwords manually from the map printed in output, or set `updateDeploymentFilesAsYaml = true` before running encryption (please note - this seems to make some whitespace changes as well)**
`customMykaarmaConfigBasePath` - only required for custom handling for authentication-utils service deployment in the API namespace (custom base path in mykaarma-config repo)
