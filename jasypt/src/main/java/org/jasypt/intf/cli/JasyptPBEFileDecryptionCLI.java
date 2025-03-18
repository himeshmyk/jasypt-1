/*
 * =============================================================================
 * 
 *   Copyright (c) 2007-2010, The JASYPT team (http://www.jasypt.org)
 * 
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 * 
 *       http://www.apache.org/licenses/LICENSE-2.0
 * 
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 * 
 * =============================================================================
 */
package org.jasypt.intf.cli;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;

import org.jasypt.commons.CommonUtils;
import org.jasypt.encryption.pbe.config.SimpleStringPBEConfig;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.intf.service.FileEncryptorService;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;


/**
 * <p>
 * This class supports the CLI "decrypt" operation for files.
 * </p>
 * <p>
 * <b>It should NEVER be used inside your code, only from the supplied
 * command-line tools</b>.
 * </p>
 * 
 * @since 1.10
 * 
 * @author Prakash Tiwari
 *
 */
public final class JasyptPBEFileDecryptionCLI {
    
    /*
     * The required arguments for this CLI operation.
     */
    private static final String[][] VALID_REQUIRED_ARGUMENTS =
        new String[][] {
            new String [] {
                ArgumentNaming.ARG_INPUT_FILE
            },
            new String [] {
                ArgumentNaming.ARG_PASSWORD
            }
        };
    
    /*
     * The optional arguments for this CLI operation.
     */
    private static final String[][] VALID_OPTIONAL_ARGUMENTS =
        new String[][] {
            new String [] {
                ArgumentNaming.ARG_OUTPUT_FILE
            },
            new String [] {
                ArgumentNaming.ARG_ENCRYPTED_PREFIX
            },
            new String [] {
                ArgumentNaming.ARG_ENCRYPTED_SUFFIX
            },
            new String [] {
                ArgumentNaming.ARG_DECRYPTED_PREFIX
            },
            new String [] {
                ArgumentNaming.ARG_DECRYPTED_SUFFIX
            },
            new String [] {
                ArgumentNaming.ARG_VERBOSE
            },
            new String [] {
                ArgumentNaming.ARG_ALGORITHM
            },
            new String [] {
                ArgumentNaming.ARG_KEY_OBTENTION_ITERATIONS
            },
            new String [] {
                ArgumentNaming.ARG_SALT_GENERATOR_CLASS_NAME
            },
            new String [] {
                ArgumentNaming.ARG_PROVIDER_NAME
            },
            new String [] {
                ArgumentNaming.ARG_PROVIDER_CLASS_NAME
            },
            new String [] {
                ArgumentNaming.ARG_STRING_OUTPUT_TYPE
            },
            new String[] {
                ArgumentNaming.ARG_IV_GENERATOR_CLASS_NAME
            }
        };

    public static String GIT_REPO_PATH = "/Users/himeshbhatia/git";
    public static String TMP_FOLDER_PATH = "/Users/himeshbhatia/Desktop/tmp";
    public static String MYKAARMA_CONFIG_REPO_PATH = GIT_REPO_PATH + "/mykaarma-config";

    public static String INTERNAL_SYSTEMS_REPO_PATH = GIT_REPO_PATH + "/internal-systems";
    public static String VISHWAKARMA_REPO_PATH = GIT_REPO_PATH + "/vishwakarma";

    private enum ENV {
        PROD("prod"),
        PROD_CANARY("prod-canary"),
        QA_AWS("qa-aws"),
        QA_AWS_CANARY("qa-aws-canary"),
        DEVVM("devvm"),
        ;

        private String value;
        ENV(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }

        public static ENV getEnumValue(String value) {
            if (value == null) {
                return null;
            }
            ENV envs[] = ENV.values();
            for (ENV env : envs) {
                if (env.getValue().equalsIgnoreCase(value)) {
                    return env;
                }
            }
            return null;
        }
    }

    public static Map<String, String> serviceToMykaarmaConfigNameMap = new HashMap<String, String>() {{
        put("kpickupdelivery-api-v2", "kpickupdelivery-api");
        put("transportation-events-consumer", "transportation-events-consumer");
        put("customer-actions-server", "customer-actions");
        put("kridesharing-api", "kridesharing-api");
        put("mobile-service-server", "mobile-service-api");
        put("transportation-route-finder", "transportation-route-finder");
        put("mobile-service-aggregator-server", "mobile-service-aggregator");
        put("mobile-check-in-server", "mobile-check-in");
        put("pickup-delivery-aggregator-server", "pickup-delivery-aggregator");
        put("kpickupdelivery-processor", "kpickupdelivery-processor");
    }};

    public static Map<String, String> serviceToApplicationYmlRelativePathMap = new HashMap<String, String>() {{
        put("email-integration", "email-integration/src/main/resources/application.yml");
        put("vault-api", "vault/server/src/main/resources/application.yml");
        put("mkhtmltopdf-api", "mkhtmltopdf/server/src/main/resources/application.yml");
    }};

    public static Map<String, Map<String, String>> serviceToEnvToJasyptPwdMap = new HashMap<>();
    public static Map<String, Map<String, String>> serviceToEnvToJasyptNewPwdMap = new HashMap<>();

    public static void fetchEnvSpecificJasyptPasswords(String namespace) {
        Map<String, String> serviceToJasyptPwdMapProd = getJasyptPasswordsForDeploymentFile(INTERNAL_SYSTEMS_REPO_PATH + "/kubernetes/" + "prod" + "/" + namespace + "/deployment.yml");
        Map<String, String> serviceToJasyptPwdMapProdCanary = getJasyptPasswordsForDeploymentFile(INTERNAL_SYSTEMS_REPO_PATH + "/kubernetes/" + "prod" + "/" + "canary" + "/deployment.yml");
        Map<String, String> serviceToJasyptPwdMapQa = getJasyptPasswordsForDeploymentFile(INTERNAL_SYSTEMS_REPO_PATH + "/kubernetes/" + "qa-aws" + "/" + namespace + "/deployment.yml");
        Map<String, String> serviceToJasyptPwdMapQaCanary = getJasyptPasswordsForDeploymentFile(INTERNAL_SYSTEMS_REPO_PATH + "/kubernetes/" + "qa-aws" + "/" + "canary" + "/deployment.yml");
        Map<String, String> serviceToJasyptPwdMapDev = getJasyptPasswordsForDeploymentFile(VISHWAKARMA_REPO_PATH + "/kubernetes/" + namespace + "/deployment.yml");

        for (String serviceName: serviceToJasyptPwdMapProd.keySet()) {
            Map<String, String> envToJasyptPwdMap = new HashMap<>();
            envToJasyptPwdMap.put(ENV.PROD.getValue(), serviceToJasyptPwdMapProd.get(serviceName));
            envToJasyptPwdMap.put(ENV.PROD_CANARY.getValue(), serviceToJasyptPwdMapProdCanary.get(serviceName + "-canary"));
            envToJasyptPwdMap.put(ENV.QA_AWS.getValue(), serviceToJasyptPwdMapQa.get(serviceName));
            envToJasyptPwdMap.put(ENV.QA_AWS_CANARY.getValue(), serviceToJasyptPwdMapQaCanary.get(serviceName + "-canary"));
            envToJasyptPwdMap.put(ENV.DEVVM.getValue(), serviceToJasyptPwdMapDev.get(serviceName));
            serviceToEnvToJasyptPwdMap.put(serviceName, envToJasyptPwdMap);
        }
    }

    public static Map<String, String> getJasyptPasswordsForDeploymentFile(String deploymentFilePath) {
        Map<String, String> serviceToJasyptPwdMap = new HashMap<>();
        Yaml yaml = new Yaml();

        // Load YAML file from resources
        try (InputStream inputStream = new FileInputStream(deploymentFilePath)) {
            if (inputStream == null) {
                throw new RuntimeException("YAML file not found!");
            }

            // Load all YAML documents
            Iterable<Object> documents = yaml.loadAll(inputStream);

            // Iterate over documents and process them
            for (Object document : documents) {
                if (document instanceof Map) {
                    Map<String, Object> data = (Map<String, Object>) document;
//                    for (String key : data.keySet()) {
//                        System.out.println("Found section: " + key + " -> " + data.get(key));
//                    }
                    String serviceName = (String) ((Map<String, Object>) data.get("metadata")).get("name");
                    List<Map<String, String>> env = (List<Map<String, String>>)
                        ((List<Map<String, Object>>)
                            ((Map<String, Object>)
                                ((Map<String, Object>)
                                    ((Map<String, Object>)
                                        (Map<String, Object>) data.get("spec"))
                                        .get("template"))
                                    .get("spec"))
                                .get("containers"))
                            .get(0).get("env");
                    if (env == null) {
                        if (printUselessLogs) System.out.println(" WARN - For " + serviceName + " - no env vars found");
                        continue;
                    }

                    Optional<Map<String, String>> jasyptPwdMap = env.stream().filter(envProp -> "jasypt.encryptor.password".equalsIgnoreCase(envProp.get("name"))).findFirst();
                    if (!jasyptPwdMap.isPresent()) {
                        System.out.println(" WARN - For " + serviceName + " - env vars doesn't contain jasypt pwd");
                        continue;
                    }
                    String jasyptPwd = jasyptPwdMap.get().get("value");
                    serviceToJasyptPwdMap.put(serviceName, jasyptPwd);
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return serviceToJasyptPwdMap;
    }

    static String namespace = "transportation";
    static boolean printUselessLogs = false;
    static boolean encrypt = false;
    static boolean shouldGenerateNewPassword = false;
    static int pwdLength = 20;


    /**
     * <p>
     * CLI execution method.
     * </p>
     * 
     * @param args the command execution arguments. Not providing the "outputFile" argument implies that
     * decryption is to be done in-place.
     */
    public static void main(String[] args) {
        fetchEnvSpecificJasyptPasswords(namespace);

//        inputFile=kpickupdelivery-api.yml
//        jasypt.encryptor.password="1CC0WGAoiIFj"
//        jasypt.encryptor.algorithm="PBEWithMD5AndDES"
//        jasypt.encryptor.key-obtention-iterations=1000
//        jasypt.encryptor.provider-name=SunJCE
//        jasypt.encryptor.salt-generator-classname=org.jasypt.salt.RandomSaltGenerator
//        jasypt.encryptor.iv-generator-classname=org.jasypt.iv.NoIvGenerator
//        jasypt.encryptor.string-output-type=base64

//        decryptFiles(args);


        for (String serviceName: serviceToEnvToJasyptPwdMap.keySet()) {
            Map<String, String> envToJasyptPwdMap = serviceToEnvToJasyptPwdMap.get(serviceName);

            if (serviceToMykaarmaConfigNameMap.containsKey(serviceName) && serviceToMykaarmaConfigNameMap.get(serviceName) != null) {
                decryptMyKaarmaConfig(args, serviceName, envToJasyptPwdMap);
            } else if (serviceToApplicationYmlRelativePathMap.containsKey(serviceName) && serviceToApplicationYmlRelativePathMap.get(serviceName) != null) {
                decryptApplicationYml(args, serviceName, envToJasyptPwdMap);
            } else {
                if (printUselessLogs) System.out.println(" WARN - For " + serviceName + " - neither serviceToMykaarmaConfigNameMap nor serviceToApplicationYmlRelativePathMap contains serviceName");
            }
        }

        System.out.println("--------serviceToEnvToJasyptNewPwdMap---------");
        System.out.println(serviceToEnvToJasyptNewPwdMap);


    }

    public static String generateRandomPassword(int length) {
        // 4 base64 chars = 3 bytes, so we generate a byte array accordingly
        int byteLength = 3 * (int) Math.ceil(length / 4.0);
        byte[] randomBytes = new byte[byteLength];

        // SecureRandom is used for cryptographic randomness
        new SecureRandom().nextBytes(randomBytes);

        // Encode to Base64 and take the required substring
        String base64String = Base64.getEncoder().encodeToString(randomBytes);
        return base64String.substring(0, length);
    }

    private static void decryptMyKaarmaConfig(String[] args, String serviceName,
        Map<String, String> envToJasyptPwdMap) {
        for (String env: envToJasyptPwdMap.keySet()) {
            if (!envToJasyptPwdMap.containsKey(env) || envToJasyptPwdMap.get(env) == null) {
                System.out.println(" WARN - For " + serviceName + " and env=" + env + " - no jasypt pwd found");
                continue;
            }
            String myKaarmaConfigPath = env + "/"
                + serviceToMykaarmaConfigNameMap.get(serviceName)
                + (isCanaryEnv(env) ? "-canary" : "")
                + ".yml";
            String jasyptPwd = envToJasyptPwdMap.get(env);
            String[] newArgs = updateArgsFromYml(args, myKaarmaConfigPath, jasyptPwd, serviceName, env);
            final String location = MYKAARMA_CONFIG_REPO_PATH + "/" ; //System.getProperty("user.dir") + "/";
            decryptFiles(location, newArgs);
        }
    }

    private static void decryptApplicationYml(String[] args, String serviceName,
        Map<String, String> envToJasyptPwdMap) {
        String applicationYmlPath = serviceToApplicationYmlRelativePathMap.get(serviceName);
        loadAndDecryptYaml(args, serviceName, applicationYmlPath, envToJasyptPwdMap);
    }

    public static void loadAndDecryptYaml(String[] args, String serviceName, String ymlPath, Map<String, String> envToJasyptPwdMap) {
        List<String> newArgs = new ArrayList<>();
        Yaml yaml = new Yaml();
        String inputYmlFilePath = GIT_REPO_PATH + "/" + ymlPath;

        List<Map<String, Object>> yamlDocumentsForThisService = new ArrayList<>();

        // Step 1: Read YAML file
        try (InputStream inputStream = new FileInputStream(inputYmlFilePath)) {
            Iterable<Object> docs = yaml.loadAll(inputStream);
            for (Object doc : docs) {
                if (doc instanceof Map) {
                    yamlDocumentsForThisService.add((Map<String, Object>) doc);
                }
            }
        } catch (IOException e) {
            System.err.println("Error reading YAML file: " + e.getMessage());
            return;
        }

        // Step 2: Process each YAML document
        List<Map<String, Object>> finalYamlDocumentsForThisService = new ArrayList<>();
        for (Map<String, Object> doc : yamlDocumentsForThisService) {
            processYamlDocument(serviceName, doc, envToJasyptPwdMap);
            finalYamlDocumentsForThisService.add(doc);
        }

        // Step 3: Write updated YAML back to file
        writeYamlToFile(inputYmlFilePath, yamlDocumentsForThisService);
    }

    private static void processYamlDocument(String serviceName, Map<String, Object> yamlData, Map<String, String> envToJasyptPwdMap) {
        try {
            // Step 1: Write the original YAML data to a temp file
            String tmpFilePath = TMP_FOLDER_PATH + "/Uyaml_temp" + (System.currentTimeMillis()%17);
            File tempFile = File.createTempFile(tmpFilePath, ".yml");
            writeYamlToFile(tempFile.getAbsolutePath(), Collections.singletonList(yamlData));

            // Step 2: Flatten values for "jasypt"
            List<String> newArgs = new ArrayList<>();
            Map<String, Object> flatYamlMap = new HashMap<>();
            if (yamlData.containsKey("jasypt")) {
                flattenYaml("jasypt", (Map<String, Object>) yamlData.get("jasypt"), flatYamlMap);
            } else {
                flatYamlMap = yamlData;
            }

            for (String[] argumentNames: VALID_OPTIONAL_ARGUMENTS) {
                if (flatYamlMap.containsKey(argumentNames[0])) {
                    newArgs.add(argumentNames[0] + "=" + flatYamlMap.get(argumentNames[0]));
                }
            }
            String jasyptPwd = getJasyptPwdFromYaml(yamlData, envToJasyptPwdMap);
            if (jasyptPwd == null) { return; }

            newArgs.add(ArgumentNaming.ARG_INPUT_FILE + "=" + tempFile.getAbsolutePath()); //inputYmlFilePath
            if (encrypt && shouldGenerateNewPassword) {
                final String newJasyptPwd = generateRandomPassword(pwdLength);
                newArgs.add(ArgumentNaming.ARG_PASSWORD + "=" + newJasyptPwd);
                String profile = ((String) yamlData.get("spring.profiles"));
                serviceToEnvToJasyptNewPwdMap.computeIfAbsent(serviceName, k -> new HashMap<>());
                serviceToEnvToJasyptNewPwdMap.get(serviceName).put(profile, newJasyptPwd);
            } else {
                newArgs.add(ArgumentNaming.ARG_PASSWORD + "=" + jasyptPwd);
            }
            // Step 3: Call decryptFiles with the flattened "jasypt" values and temp file path
            decryptFiles("", newArgs.toArray(new String[newArgs.size()]));

            // Step 4: Read decrypted YAML from the temp file and update yamlData
            Yaml yaml = new Yaml();
            try (InputStream inputStream = new FileInputStream(tempFile.getAbsolutePath())) {
                // Load all YAML documents
                Map<String, Object> decryptedYaml = (Map<String, Object>) yaml.loadAll(inputStream).iterator().next();
                if (decryptedYaml != null) {
                    yamlData.putAll(decryptedYaml);
                }
            }
        } catch (IOException e) {
            System.err.println("Error processing YAML document: " + e.getMessage());
        }
    }

    private static String getJasyptPwdFromYaml(Map<String, Object> yamlData, Map<String, String> envToJasyptPwdMap) {
        if (!yamlData.containsKey("spring.profiles")
            || ((String) yamlData.get("spring.profiles")) == null
            || ENV.getEnumValue(((String) yamlData.get("spring.profiles"))) == null) {
            System.out.println(" WARN - For  + serviceName +  and env= + env +  - no jasypt pwd found");
            return null;
        }

        String profile = ((String) yamlData.get("spring.profiles"));
        String jasyptPwd = envToJasyptPwdMap.get(profile);
        return jasyptPwd;
    }

    private static void writeYamlToFile(String filePath, List<Map<String, Object>> yamlDocuments) {
        DumperOptions options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);

        Yaml yaml = new Yaml(options);

        try (BufferedWriter writer = Files.newBufferedWriter(Paths.get(filePath))) {
            for (Map<String, Object> doc : yamlDocuments) {
                writer.write(yaml.dump(doc));
                writer.write("---\n");  // Separate YAML documents
            }
        } catch (IOException e) {
            System.err.println("Error writing YAML file: " + e.getMessage());
        }
    }

    public static boolean isCanaryEnv(String env) {
        return ENV.PROD_CANARY.getValue().equalsIgnoreCase(env) || ENV.QA_AWS_CANARY.getValue().equalsIgnoreCase(env);
    }

    // Recursively flatten the nested YAML map
    private static void flattenYaml(String parentKey, Map<String, Object> yamlMap, Map<String, Object> flatMap) {
        for (Map.Entry<String, Object> entry : yamlMap.entrySet()) {
            String key = parentKey.isEmpty() ? entry.getKey() : parentKey + "." + entry.getKey();

            if (entry.getValue() instanceof Map) {
                // Recursively flatten nested maps
                flattenYaml(key, (Map<String, Object>) entry.getValue(), flatMap);
            } else {
                // Store flattened key-value pair
//                flatMap.put(key, String.valueOf(entry.getValue()));
                flatMap.put(key, entry.getValue());
            }
        }
    }

    public static String[] updateArgsFromYml(String[] args, String ymlPath, String jasyptPwd, String serviceName, String env) {
        List<String> newArgs = new ArrayList<>();
        Yaml yaml = new Yaml();
        String inputYmlFilePath = MYKAARMA_CONFIG_REPO_PATH + "/" + ymlPath;

        // Load YAML file from resources
        try (InputStream inputStream = new FileInputStream(inputYmlFilePath)) {
            if (inputStream == null) {
                throw new RuntimeException("YAML file not found!");
            }

            // Load all YAML documents
            Iterable<Object> documents = yaml.loadAll(inputStream);

            // Iterate over documents and process them
            for (Object document : documents) {
                if (document instanceof Map) {
                    Map<String, Object> data = (Map<String, Object>) document;
                    // Flatten the YAML structure
                    Map<String, Object> flatYamlMap = new HashMap<>();
                    if (data.containsKey("jasypt")) {
                        flattenYaml("jasypt", (Map<String, Object>) data.get("jasypt"), flatYamlMap);
                    } else {
                        flatYamlMap = data;
                    }

                    for (String[] argumentNames: VALID_OPTIONAL_ARGUMENTS) {
                        if (flatYamlMap.containsKey(argumentNames[0])) {
                            newArgs.add(argumentNames[0] + "=" + flatYamlMap.get(argumentNames[0]));
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        newArgs.add(ArgumentNaming.ARG_INPUT_FILE + "=" + ymlPath); //inputYmlFilePath
        if (encrypt && shouldGenerateNewPassword) {
            final String newJasyptPwd = generateRandomPassword(pwdLength);
            newArgs.add(ArgumentNaming.ARG_PASSWORD + "=" + newJasyptPwd);
            serviceToEnvToJasyptNewPwdMap.computeIfAbsent(serviceName, k -> new HashMap<>());
            serviceToEnvToJasyptNewPwdMap.get(serviceName).put(env, newJasyptPwd);
        } else {
            newArgs.add(ArgumentNaming.ARG_PASSWORD + "=" + jasyptPwd);
        }
        return newArgs.toArray(new String[newArgs.size()]);
    }

    public static void decryptFiles(String location, String[] args) {
        boolean verbose = CLIUtils.getVerbosity(args);
        try {

            String applicationName = null;
            String[] arguments = null;
            if (args[0] == null || args[0].indexOf("=") != -1) {
                applicationName = JasyptPBEFileDecryptionCLI.class.getName();
                arguments = args;
            } else {
                applicationName = args[0];
                arguments = new String[args.length - 1];
                System.arraycopy(args, 1, arguments, 0, args.length - 1);
            }

            final Properties argumentValues =
                CLIUtils.getArgumentValues(
                    applicationName, arguments,
                    VALID_REQUIRED_ARGUMENTS, VALID_OPTIONAL_ARGUMENTS);

            CLIUtils.showEnvironment(verbose);

            CLIUtils.showArgumentDescription(argumentValues, verbose);

            final String outputFilePath = decryptFile(location, argumentValues, verbose);

            final String result = "Decryption complete and is written at: " + outputFilePath;

            CLIUtils.showOutput(result, verbose);

        } catch (Throwable t) {
            CLIUtils.showError(t, verbose);
        }
    }
    
    /**
     * <p>
     * Performs decryption operation on a file by identifying parameters from CLI Arguments
     * </p>
     * 
     * @param location The base location to perform I/O operations
     * @param argumentValues
     * @param verbose
     * @return The output file path where decrypted file is saved
     * @throws IOException if there's some exception while reading/writing the files.
     * @throws EncryptionOperationNotPossibleException if the decryption operation could
     *         not be performed on any of the values (either because of wrong input or wrong
     *         parameterization).
     */
    private static String decryptFile(
            final String location,
            final Properties argumentValues,
            final boolean verbose) throws IOException {
        
        String encryptedPrefix = argumentValues.getProperty(ArgumentNaming.ARG_ENCRYPTED_PREFIX);
        String encryptedSuffix = argumentValues.getProperty(ArgumentNaming.ARG_ENCRYPTED_SUFFIX);
        String decryptedPrefix = argumentValues.getProperty(ArgumentNaming.ARG_DECRYPTED_PREFIX);
        String decryptedSuffix = argumentValues.getProperty(ArgumentNaming.ARG_DECRYPTED_SUFFIX);
        
        final String inputFileName = argumentValues.getProperty(ArgumentNaming.ARG_INPUT_FILE);
        final String password = argumentValues.getProperty(ArgumentNaming.ARG_PASSWORD);
        CommonUtils.validateNotEmpty(inputFileName, "Input file name cannot be null/empty");
        CommonUtils.validateNotEmpty(password, "Password cannot be null/empty");
        
        final String inputFilePath = location + inputFileName;
        final String inputFileAsString = CommonUtils.getFileAsString(inputFilePath);
        
        SimpleStringPBEConfig config = new SimpleStringPBEConfig();
        config.setPassword(password);
        config.setAlgorithm(argumentValues.getProperty(ArgumentNaming.ARG_ALGORITHM));
        config.setKeyObtentionIterations(argumentValues.getProperty(ArgumentNaming.ARG_KEY_OBTENTION_ITERATIONS));
        config.setSaltGeneratorClassName(argumentValues.getProperty(ArgumentNaming.ARG_SALT_GENERATOR_CLASS_NAME));
        config.setProviderName(argumentValues.getProperty(ArgumentNaming.ARG_PROVIDER_NAME));
        config.setProviderClassName(argumentValues.getProperty(ArgumentNaming.ARG_PROVIDER_CLASS_NAME));
        config.setStringOutputType(argumentValues.getProperty(ArgumentNaming.ARG_STRING_OUTPUT_TYPE));
        config.setIvGeneratorClassName(argumentValues.getProperty(ArgumentNaming.ARG_IV_GENERATOR_CLASS_NAME));
        
        final FileEncryptorService fileEncryptorService = new FileEncryptorService();

        String outputFileAsString;
        if (encrypt) {
            outputFileAsString = fileEncryptorService.encrypt(
                inputFileAsString, config, encryptedPrefix, encryptedSuffix, decryptedPrefix,
                decryptedSuffix, verbose
            );
        } else {
            outputFileAsString = fileEncryptorService.decrypt(
                inputFileAsString, config, encryptedPrefix, encryptedSuffix, decryptedPrefix,
                decryptedSuffix, verbose
            );
        }
        
        final String outputFileName = argumentValues.getProperty(ArgumentNaming.ARG_OUTPUT_FILE);
        String outputFilePath = null;
        
        if(CommonUtils.isEmpty(outputFileName)) {
            outputFilePath = inputFilePath;
        } else {
            outputFilePath = location + outputFileName;
        }
        
        CommonUtils.writeStringToFile(outputFilePath, outputFileAsString);
        
        return outputFilePath;
    }
    
    
    /*
     * Instantiation is forbidden.
     */
    private JasyptPBEFileDecryptionCLI() {
        super();
    }
    
}
