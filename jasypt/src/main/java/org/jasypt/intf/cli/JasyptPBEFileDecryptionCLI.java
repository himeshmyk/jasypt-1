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

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.jasypt.commons.CommonUtils;
import org.jasypt.encryption.pbe.config.SimpleStringPBEConfig;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.intf.service.FileEncryptorService;
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
    public static String MYKAARMA_CONFIG_REPO_PATH = GIT_REPO_PATH + "/mykaarma-config";

    public static String INTERNAL_SYSTEMS_REPO_PATH = GIT_REPO_PATH + "/internal-systems";

    public static String namespace = "transportation", env = "prod";

    public static Map<String, String> serviceToJasyptPwdMap = new HashMap<>();

    public static void getDeployments() {
        Yaml yaml = new Yaml();

        // Load YAML file from resources
        try (InputStream inputStream = new FileInputStream(INTERNAL_SYSTEMS_REPO_PATH + "/kubernetes/" + env + "/" + namespace + "/deployment.yml")) {
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
                    System.out.println(env);
                    String jasyptPwd = env.stream().filter(envProp -> "jasypt.encryptor.password".equalsIgnoreCase(envProp.get("name"))).findFirst().get().get("value");
                    System.out.println(jasyptPwd);
                }
            }

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
    public static void main(final String[] args) {

        getDeployments();

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

            final String location = MYKAARMA_CONFIG_REPO_PATH + "/prod/" ; //System.getProperty("user.dir") + "/";

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
        
        String outputFileAsString = fileEncryptorService.decrypt(
        		inputFileAsString, config, encryptedPrefix, encryptedSuffix, decryptedPrefix, decryptedSuffix, verbose
        		);
        
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
