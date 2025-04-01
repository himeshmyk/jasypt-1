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
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;

import java.util.Set;
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

    //ARGUMENTS:

//    static String namespace = "api";  //custom handling for auth utils deployment in api namespace
    static String namespace = "dms";
    static String specificServiceName = "korder-api-v2";
    static String specificEnv = "";
//    static String specificEnv = "qa-aws";
    static boolean printUselessLogs = false;
    static boolean encrypt = false;
    static boolean shouldGenerateNewPassword = false;
    static int pwdLength = 20;
    static boolean updateDeploymentFilesAsYaml = false;
    static String customMykaarmaConfigBasePath = "";
//    static String customMykaarmaConfigBasePath = "qa-aws-api";


    //1. all services transportation
    //2. reporting->mk-planetscale-connector
    //3. archext->mkurlshortener--server and archext->authentication-utils--server



    //MODIFY ACCORDING TO YOUR SYSTEM/REPOS/NAMESPACE
    public static String GIT_REPO_PATH = "/Users/himeshbhatia/git";
    public static String TMP_FOLDER_PATH = "/Users/himeshbhatia/Desktop/tmp";
    public static String MYKAARMA_CONFIG_REPO_PATH = GIT_REPO_PATH + "/mykaarma-config";

    public static String INTERNAL_SYSTEMS_REPO_PATH = GIT_REPO_PATH + "/internal-systems";
    public static String VISHWAKARMA_REPO_PATH = GIT_REPO_PATH + "/vishwakarma";

    public static Map<String, String> serviceToMykaarmaConfigNameMap = new HashMap<String, String>() {{
        put("authentication-utils--server", "authentication-utils-server");
        put("mkurlshortener--server", "mkUrlShortener-server");
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
        put("mk-planetscale-connector", "mk-planetscale-connector");

        put("calendar-api--server", "calendar-api");
        put("leads-service", "leads-service");
    }};

    public static Map<String, String> serviceToApplicationYmlRelativePathMap = new HashMap<String, String>() {{
        put("email-integration", "email-integration/src/main/resources/application.yml");
        put("vault-api", "vault/server/src/main/resources/application.yml");
        put("mkhtmltopdf-api", "mkhtmltopdf/server/src/main/resources/application.yml");
        put("korder-api-v2", "korder-api/server/src/main/resources/application.yml");
    }};

    public static Map<String, Map<String, String>> serviceToEnvToJasyptPwdMap = new HashMap<>();
    public static Map<String, Map<String, String>> envToServiceToJasyptNewPwdMap = new HashMap<>();

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

    public static String getDeploymentFilePath(ENV env) {
        switch (env) {
            case PROD:
                return INTERNAL_SYSTEMS_REPO_PATH + "/kubernetes/" + "prod" + "/" + namespace + "/deployment.yml";
            case PROD_CANARY:
                return INTERNAL_SYSTEMS_REPO_PATH + "/kubernetes/" + "prod" + "/" + "canary" + "/deployment.yml";
            case QA_AWS:
                return INTERNAL_SYSTEMS_REPO_PATH + "/kubernetes/" + "qa-aws" + "/" + namespace + "/deployment.yml";
            case QA_AWS_CANARY:
                return INTERNAL_SYSTEMS_REPO_PATH + "/kubernetes/" + "qa-aws" + "/" + "canary" + "/deployment.yml";
            case DEVVM:
                return VISHWAKARMA_REPO_PATH + "/kubernetes/" + namespace + "/deployment.yml";
        }
        return null;
    }

    public static void fetchEnvSpecificJasyptPasswords(String namespace) {
        Set<String> serviceNames = null;
        Map<String, String> serviceToJasyptPwdMapProd = !shouldProcessForThisEnv(ENV.PROD.getValue()) ? new HashMap<>() :
            getJasyptPasswordsForDeploymentFile(getDeploymentFilePath(ENV.PROD));
        if (isSpecificEnvMatching(ENV.PROD)) { serviceNames = serviceToJasyptPwdMapProd.keySet(); }
        Map<String, String> serviceToJasyptPwdMapProdCanary = !shouldProcessForThisEnv(ENV.PROD_CANARY.getValue()) ? new HashMap<>() :
            getJasyptPasswordsForDeploymentFile(getDeploymentFilePath(ENV.PROD_CANARY));
        if (isSpecificEnvMatching(ENV.PROD_CANARY)) { serviceNames = serviceToJasyptPwdMapProdCanary.keySet(); }
        Map<String, String> serviceToJasyptPwdMapQa = !shouldProcessForThisEnv(ENV.QA_AWS.getValue()) ? new HashMap<>() :
            getJasyptPasswordsForDeploymentFile(getDeploymentFilePath(ENV.QA_AWS));
        if (isSpecificEnvMatching(ENV.QA_AWS)) { serviceNames = serviceToJasyptPwdMapQa.keySet(); }
        Map<String, String> serviceToJasyptPwdMapQaCanary = !shouldProcessForThisEnv(ENV.QA_AWS_CANARY.getValue()) ? new HashMap<>() :
            getJasyptPasswordsForDeploymentFile(getDeploymentFilePath(ENV.QA_AWS_CANARY));
        if (isSpecificEnvMatching(ENV.QA_AWS_CANARY)) { serviceNames = serviceToJasyptPwdMapQaCanary.keySet(); }
        Map<String, String> serviceToJasyptPwdMapDev = !shouldProcessForThisEnv(ENV.DEVVM.getValue()) ? new HashMap<>() :
            getJasyptPasswordsForDeploymentFile(getDeploymentFilePath(ENV.DEVVM));
        if (isSpecificEnvMatching(ENV.DEVVM)) { serviceNames = serviceToJasyptPwdMapDev.keySet(); }

        if (!isSpecificEnvPresent()) { serviceNames = serviceToJasyptPwdMapProd.keySet(); }

        for (String serviceName: serviceNames) {
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
                    List<Map<String, String>> envVars = (List<Map<String, String>>)
                        ((List<Map<String, Object>>)
                            ((Map<String, Object>)
                                ((Map<String, Object>)
                                    ((Map<String, Object>)
                                        (Map<String, Object>) data.get("spec"))
                                        .get("template"))
                                    .get("spec"))
                                .get("containers"))
                            .get(0).get("env");
                    if (envVars == null) {
                        if (printUselessLogs) System.out.println(" WARN - For " + serviceName + " - no env vars found");
                        continue;
                    }

                    Optional<Map<String, String>> jasyptPwdMap = envVars.stream().filter(envProp -> "jasypt.encryptor.password".equalsIgnoreCase(envProp.get("name"))).findFirst();
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

    public static void updatePwdInFile(String env, Map<String, String> serviceToJasyptNewPwdMap) {
        String deploymentFilePath = getDeploymentFilePath(ENV.getEnumValue(env));

        // Create a hashmap with keys and replacement values
        Map<String, String> replacements = getReplacementMap(env, serviceToJasyptNewPwdMap);

        try {
            // Read the file content
            String content = new String(Files.readAllBytes(Paths.get(deploymentFilePath)));

            // Replace occurrences of each key with its value
            for (Map.Entry<String, String> entry : replacements.entrySet()) {
                content = content.replace(entry.getKey(), entry.getValue());
            }

            // Write the modified content back to the file
            Files.write(Paths.get(deploymentFilePath), content.getBytes());

            System.out.println("File updated successfully.");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static Map<String, String> getReplacementMap(String env, Map<String, String> serviceToJasyptNewPwdMap) {
        Map<String, String> replacementMap = new HashMap<>();
        for (String serviceName: serviceToJasyptNewPwdMap.keySet()) {
            replacementMap.put(serviceToEnvToJasyptPwdMap.get(serviceName).get(env), serviceToJasyptNewPwdMap.get(serviceName));
        }
        return replacementMap;
    }

    public static void updateJasyptPasswordInDeploymentFile(String env, Map<String, String> serviceToJasyptNewPwdMap) {
        if (!updateDeploymentFilesAsYaml) {
            updatePwdInFile(env, serviceToJasyptNewPwdMap);
            return;
        }


        String deploymentFilePath = getDeploymentFilePath(ENV.getEnumValue(env));
        Yaml yaml = new Yaml();

        // Load YAML file from resources
        try (InputStream inputStream = new FileInputStream(deploymentFilePath)) {
            if (inputStream == null) {
                throw new RuntimeException("YAML file not found!");
            }

            // Load all YAML documents
            Iterable<Object> documents = yaml.loadAll(inputStream);

            // Iterate over documents and process them
            List<Map<String, Object>> deploymentYmlsForThisFilePath = new ArrayList<>();
            for (Object document : documents) {
                if (document instanceof Map) {
                    Map<String, Object> data = (Map<String, Object>) document;
                    deploymentYmlsForThisFilePath.add(data);
//                    for (String key : data.keySet()) {
//                        System.out.println("Found section: " + key + " -> " + data.get(key));
//                    }
                    String serviceName = (String) ((Map<String, Object>) data.get("metadata")).get("name");
                    String baseServiceName = isCanaryEnv(env) ? serviceName.substring(0, serviceName.indexOf("-canary")) : serviceName;
                    if (!serviceToJasyptNewPwdMap.containsKey(baseServiceName) || serviceToJasyptNewPwdMap.get(baseServiceName) == null) {
                        continue;
                    }
                    String newJasyptPwd = serviceToJasyptNewPwdMap.get(baseServiceName);

                    List<Map<String, String>> envVars = (List<Map<String, String>>)
                        ((List<Map<String, Object>>)
                            ((Map<String, Object>)
                                ((Map<String, Object>)
                                    ((Map<String, Object>)
                                        (Map<String, Object>) data.get("spec"))
                                        .get("template"))
                                    .get("spec"))
                                .get("containers"))
                            .get(0).get("env");
                    if (envVars == null) {
                        if (printUselessLogs) System.out.println(" WARN - For " + serviceName + " - no env vars found");
                        continue;
                    }

                    Optional<Map<String, String>> jasyptPwdMap = envVars.stream().filter(envProp -> "jasypt.encryptor.password".equalsIgnoreCase(envProp.get("name"))).findFirst();
                    if (!jasyptPwdMap.isPresent()) {
                        System.out.println(" WARN - For " + serviceName + " - env vars doesn't contain jasypt pwd");
                        continue;
                    }
                    jasyptPwdMap.get().put("value", newJasyptPwd);
//                    System.out.print(data);
                }
            }

            writeYamlToFile(deploymentFilePath, deploymentYmlsForThisFilePath);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


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


        Map<String, Map<String, String>> fetchedEnvToServiceToJasyptPwdMap = new HashMap<>();
        for (String serviceName: serviceToEnvToJasyptPwdMap.keySet()) {
            Map<String, String> envToJasyptPwdMap = serviceToEnvToJasyptPwdMap.get(serviceName);
            if (envToJasyptPwdMap != null) {
                for (String env: envToJasyptPwdMap.keySet()) {
                    fetchedEnvToServiceToJasyptPwdMap.computeIfAbsent(env,
                        k -> new HashMap<>());
                    fetchedEnvToServiceToJasyptPwdMap.get(env).put(serviceName, envToJasyptPwdMap.get(env));
                }
            }
        }

        System.out.println("--------fetchedEnvToServiceToJasyptPwdMap---------");
        System.out.println(fetchedEnvToServiceToJasyptPwdMap);


        for (String serviceName: serviceToEnvToJasyptPwdMap.keySet()) {

            if (specificServiceName != null && !specificServiceName.equals("") && !specificServiceName.contentEquals(serviceName)) { continue; }

            Map<String, String> envToJasyptPwdMap = serviceToEnvToJasyptPwdMap.get(serviceName);

            if (serviceToMykaarmaConfigNameMap.containsKey(serviceName) && serviceToMykaarmaConfigNameMap.get(serviceName) != null) {
                decryptMyKaarmaConfig(args, serviceName, envToJasyptPwdMap);
            } else if (serviceToApplicationYmlRelativePathMap.containsKey(serviceName) && serviceToApplicationYmlRelativePathMap.get(serviceName) != null) {
                decryptApplicationYml(args, serviceName, envToJasyptPwdMap);
            } else {
                if (printUselessLogs) System.out.println(" WARN - For " + serviceName + " - neither serviceToMykaarmaConfigNameMap nor serviceToApplicationYmlRelativePathMap contains serviceName");
            }
        }

        System.out.println("--------envToServiceToJasyptNewPwdMap---------");
        System.out.println(envToServiceToJasyptNewPwdMap);

        updatePasswordsInDeploymentFiles();


    }

    public static void updatePasswordsInDeploymentFiles() {
        for (String env: envToServiceToJasyptNewPwdMap.keySet()) {
            if (!shouldProcessForThisEnv(env)) {
                continue;
            }
            if (!envToServiceToJasyptNewPwdMap.containsKey(env)
                || envToServiceToJasyptNewPwdMap.get(env) == null
                || envToServiceToJasyptNewPwdMap.get(env).isEmpty()) {
                continue;
            }
            Map<String, String> serviceToJasyptNewPwdMap = envToServiceToJasyptNewPwdMap.get(env);
            updateJasyptPasswordInDeploymentFile(env, serviceToJasyptNewPwdMap);
        }
    }

    public static String generateRandomPassword(int length) {
        // 4 base64 chars = 3 bytes, so we generate a byte array accordingly
        int byteLength = 3 * (int) Math.ceil(length / 4.0);
        byte[] randomBytes = new byte[byteLength];

        // SecureRandom is used for cryptographic randomness
        new SecureRandom().nextBytes(randomBytes);

//        // Encode to Base64 and take the required substring
//        String base64String = Base64.getEncoder().encodeToString(randomBytes);
//        return base64String.substring(0, length);

        // Convert bytes to hex string
        StringBuilder hexString = new StringBuilder();
        for (byte b : randomBytes) {
            hexString.append(String.format("%02x", b)); // Format as two-digit hex
        }

        // Trim to requested length
        return hexString.substring(0, length);
    }

    private static void decryptMyKaarmaConfig(String[] args, String serviceName,
        Map<String, String> envToJasyptPwdMap) {
        for (String env: envToJasyptPwdMap.keySet()) {
            if (!shouldProcessForThisEnv(env)) {
                continue;
            }
            if (!envToJasyptPwdMap.containsKey(env) || envToJasyptPwdMap.get(env) == null) {
                System.out.println(" WARN - For " + serviceName + " and env=" + env + " - no jasypt pwd found");
                continue;
            }
            String myKaarmaConfigPath = (isEmpty(customMykaarmaConfigBasePath) ? env : customMykaarmaConfigBasePath) + "/"
                + serviceToMykaarmaConfigNameMap.get(serviceName)
                + (isCanaryEnv(env) ? "-canary" : "")
                + ".yml";
            String jasyptPwd = envToJasyptPwdMap.get(env);
            String[] newArgs = updateArgsFromYml(args, myKaarmaConfigPath, jasyptPwd, serviceName, env);
            final String location = MYKAARMA_CONFIG_REPO_PATH + "/" ; //System.getProperty("user.dir") + "/";
            decryptFiles(location, newArgs);
        }
    }

    public static boolean isEmpty(String s) {
        return s == null || s.isEmpty();
    }

    private static void decryptApplicationYml(String[] args, String serviceName,
        Map<String, String> envToJasyptPwdMap) {
        String applicationYmlPath = serviceToApplicationYmlRelativePathMap.get(serviceName);
        loadAndDecryptYaml(args, serviceName, applicationYmlPath, envToJasyptPwdMap);
    }

    public static void loadAndDecryptYaml(String[] args, String serviceName, String ymlPath, Map<String, String> envToJasyptPwdMap) {
        String inputYmlFilePath = GIT_REPO_PATH + "/" + ymlPath;
        try {
            // Step 1: Read the entire file content as plain text
            String content = new String(Files.readAllBytes(Paths.get(inputYmlFilePath)));

            // Step 2: Split content into sections using "---" as the delimiter (handling multi-line separator)
            String[] sections = content.split("(?m)^---$");

            // Step 3: Initialize a StringBuilder to collect processed sections
            StringBuilder processedContent = new StringBuilder();

            for (int i = 0; i < sections.length; i++) {
                String section = sections[i];
                section = section.trim();
                if (section.isEmpty()) continue;

                // Step 4: Process each section
                String processedSection = processYamlSection(section, serviceName, envToJasyptPwdMap);
                processedContent.append(processedSection);
                if (i == sections.length - 1) {
                    processedContent.append("\n");
                } else {
                    processedContent.append("\n---\n");
                }
            }

            // Step 5: Write the processed content back to the original file
            Files.write(Paths.get(inputYmlFilePath), processedContent.toString().getBytes());
            System.out.println("Processed YAML file successfully.");

        } catch (IOException e) {
            System.err.println("Error processing YAML file: " + e.getMessage());
        }
    }

    private static String processYamlSection(String section, String serviceName, Map<String, String> envToJasyptPwdMap) {
        try {
            // Step 1: Create a temporary file
            File tempFile = File.createTempFile("yaml_section_" + System.currentTimeMillis(), ".yml");

            // Initialize SnakeYAML parser
            Yaml yaml = new Yaml();

            // Parse the YAML string into a Map
            Map<String, Object> yamlData = yaml.load(section);

            String profile = ((String) yamlData.get("spring.profiles"));
            if (isEmpty(profile) || !shouldProcessForThisEnv(profile)) { return section; }

            String jasyptPwd = getJasyptPwdFromYaml(yamlData, envToJasyptPwdMap);
            if (jasyptPwd == null) { return section; }

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

            // Step 2: Write the current section to the temp file
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(tempFile))) {
                writer.write(section);
            }

            // Step 3: Call the decryptFile method with the temp file path
            List<String> deepCopy = new ArrayList<>(newArgs);
            deepCopy.add(ArgumentNaming.ARG_INPUT_FILE + "=" + tempFile.getAbsolutePath()); //inputYmlFilePath
            if (encrypt && shouldGenerateNewPassword) {
                final String newJasyptPwd = generateRandomPassword(pwdLength);
                deepCopy.add(ArgumentNaming.ARG_PASSWORD + "=" + newJasyptPwd);
                updateNewJasyptPwdInMap(profile, serviceName, newJasyptPwd);
            } else {
                deepCopy.add(ArgumentNaming.ARG_PASSWORD + "=" + jasyptPwd);
            }
            decryptFiles("", deepCopy.toArray(new String[deepCopy.size()]));

            // Step 4: Read the processed content from the temp file
            String processedSection = new String(Files.readAllBytes(tempFile.toPath()));

            // Step 5: Clean up the temp file
            tempFile.delete();

            return processedSection.trim();
        } catch (IOException e) {
            System.err.println("Error processing YAML section: " + e.getMessage());
            return section;  // Return the original section in case of error
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
        if (!shouldProcessForThisEnv(profile)) {
            return null;
        }
        String jasyptPwd = envToJasyptPwdMap.get(profile);
        return jasyptPwd;
    }

    public static boolean shouldProcessForThisEnv(String env) {
        if (!isSpecificEnvPresent()) { return true; }
        return env.contentEquals(specificEnv);
    }

    public static boolean isSpecificEnvPresent() {
        return !isEmpty(specificEnv);
    }

    public static boolean isSpecificEnvMatching(ENV env) {
        return (env.getValue().contentEquals(specificEnv));
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
            updateNewJasyptPwdInMap(env, serviceName, newJasyptPwd);
        } else {
            newArgs.add(ArgumentNaming.ARG_PASSWORD + "=" + jasyptPwd);
        }
        return newArgs.toArray(new String[newArgs.size()]);
    }

    public static void updateNewJasyptPwdInMap(String profile, String serviceName, String newJasyptPwd) {
        envToServiceToJasyptNewPwdMap.computeIfAbsent(profile, k -> new HashMap<>());
        envToServiceToJasyptNewPwdMap.get(profile).put(serviceName, newJasyptPwd);
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
