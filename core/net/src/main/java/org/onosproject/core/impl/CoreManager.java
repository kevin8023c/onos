/*
 * Copyright 2014-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.onosproject.core.impl;

import org.onlab.metrics.MetricsService;
import org.onlab.util.SharedExecutors;
import org.onlab.util.SharedScheduledExecutors;
import org.onlab.util.Tools;
import org.onosproject.app.ApplicationIdStore;
import org.onosproject.app.ApplicationService;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.core.IdBlockStore;
import org.onosproject.core.IdGenerator;
import org.onosproject.core.Version;
import org.onosproject.core.VersionService;
import org.onosproject.event.EventDeliveryService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Dictionary;
import java.util.Set;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetAddress;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.onosproject.net.OsgiPropertyConstants.CALCULATE_PERFORMANCE_CHECK;
import static org.onosproject.net.OsgiPropertyConstants.CALCULATE_PERFORMANCE_CHECK_DEFAULT;
import static org.onosproject.net.OsgiPropertyConstants.MAX_EVENT_TIME_LIMIT;
import static org.onosproject.net.OsgiPropertyConstants.MAX_EVENT_TIME_LIMIT_DEFAULT;
import static org.onosproject.net.OsgiPropertyConstants.SHARED_THREAD_POOL_SIZE;
import static org.onosproject.net.OsgiPropertyConstants.SHARED_THREAD_POOL_SIZE_DEFAULT;
import static org.onosproject.security.AppGuard.checkPermission;
import static org.onosproject.security.AppPermission.Type.APP_READ;
import static org.onosproject.security.AppPermission.Type.APP_WRITE;

/**
 * Core service implementation.
 */
@Component(
        immediate = true,
        service = CoreService.class,
        property = {
                SHARED_THREAD_POOL_SIZE + ":Integer=" + SHARED_THREAD_POOL_SIZE_DEFAULT,
                MAX_EVENT_TIME_LIMIT + ":Integer=" + MAX_EVENT_TIME_LIMIT_DEFAULT,
                CALCULATE_PERFORMANCE_CHECK + ":Boolean=" + CALCULATE_PERFORMANCE_CHECK_DEFAULT
        }
)
public class CoreManager implements CoreService {

    private final Logger log = LoggerFactory.getLogger(getClass());

    /**
     * Server Private Key
     */
    private static final String SERVER_PRIV_KEY_HEX = "308204BF020100300D06092A864886F70D0101010500048204A9308204A50201000282010100D4A485421621D4DD944BFB5CAE3F8D0B09C5AF284052B549A2F3AAA59D92E56A293183ABB5FEF7DBA44CE0FEBC6A78E107E283C17627737BA138AEAD3F202CE0B0F73A38B3998C0F77F421047CC33369D4E2C6680963EC1CCA2D8FD46C6E3F1974BC061E99512F3BCE8E0590E80C0AC4EAFF3ED7C83E33EF5C2EA79C3901667A078ECB3E199E1BA6E80A6AEA1F004CF7EBA34B2F306279F337419CDAA548285428652AB9AA00C7BD5B02B863844BA9A329DBCB03E0747BA3FFC9DAC278615C3B72A2153CE6DD9DEF46FCC5EDF604DC9C9414DD6D47C562A38D5D8EDEB6219D3EA85F9FF42F2AE3A00A9DC2AE243299B7819430B43DC3BCA17A08FC3E082758E102030100010282010100A4074CEC0F9A85536F63B54067018AD12AF69D08D5A577469836923A32F4EF9716B3A5383DA9B294718704403C237D9F48AFC8A6E177C93362C810A67F7D5860F2E1A2BDBE7D0177A5366289CD9BDDFB1346E379B954A4FC08516113A198E17FC7768AD9EBB69E52EA20CFD659C9803D2A713E8EC15E8A3D67C46D72AADE93A6C25B75885D5A2B49C9205B94C5A64A92ECF8AB83BF4F4FF7C43DC1BB441C9D7A2CC67F6E340E3F41A66997052D05513A28B26C2A65D6973088C89F0002FF393B1C79023D508C780914AB6DFF48CC7131302053AB43ABEB05FA23D26C5AF35C6E8C24261C7D2806B168EA604D7C786D8C43A36D1C617E188999D7171290E6038902818100EA884B2B5710ABB6B1FD3BCD3E4CB4285E95EE1B61C134F76AED9018540A3DF76B6F2BF1F413279BD14F1E5136BA23C82AEFD1176306AD28A2EB8005FDDD8B6FD1EBACFB692C67BC4C1DE250906ECDF06D1515828C6FE06CE6030315E5E9F589F6FDD44323B892AF0C27B9AB1479D479B80E9B3B08BC80649B328E54CCA790BB02818100E81B4B0E2320DAA27FA10E64F3715466CA9EFD105972359579E164B184227375442F061425CC2583B2B3E36724AB826F567BD11ACB4E7C7B4D58D2195EE14B3D1741F45249FB19DFBF0B12C18C89FC2BBEE0BAECCFB1EBD101616E1957B02602883AB37E3A29D51770E7F77379D4BBB28DF63DD6B6C34480EAC8EF3C06F6A1130281810085CA5E6748F19FA3470218FD4A8EE32F2C560750E3811E400E659B0FE5D139EC4D034C6468420D145C60F0009061BB4BD3029F9AE1C8CB3B254586F0E4136019D7FCC3DF5FEE0EF761CCA2702714AEB27AE7CE2F7D01CD5B1213A1CCFA2D6EFED74191B70347A595EA2F37419B1AACD50AE47A3541149781CCEF1836D3D0BB4502818006F932F314C91AE880EF24D091A3D90651961F424B7DABF076BDF7D9817FCB7A3D77303690C0266C63851612F63E14E8257008E346327078FFE4E8430CDFB5F3FAEBE75C458EBEC34329210221A7CFA4BCD261AB55BE21B8A0D2FD8CD35E9E75BB04107A7D62DE5D1AEE4D37F1F41B438D1255DF4A94694D7A405937B379DB7302818100AB926FBBEC0EC2150EAE2D1AD6C52BED7179C6AA1EE68EAB47000420D16A06BCB3EC50269818EF4C6930EE87FBBAC389F6EDB400BB68E8932FE887EA016B93160DC35E43A4AA5F9BED05C6EAD9A691E19828ADF11FA994037FB53831C499D86A50287142C6DEFBDF9C33DE4129AD64F5477FBCEE927EC95F344278014B3797D6";

    /**
     * Client Public Key
     */
    private static final String CLIENT_PUBLIC_KEY_HEX = "30820122300D06092A864886F70D01010105000382010F003082010A028201010084020B2CFD1BE4E3050555F7A4747A30BF7349D5D5D8767BC5B30FD624916E264217F97599FF1B5F09AEE97E80F8851D5DA61EED9D8A4CBE67CBB6389C59874457D83B23BBC4D92EA7F3303E0BA5AA69A03CBF6639DEE6ECA1A73C47BD3D4998EE0332836ED5DEF91A0C01352AAEE6458D05FB1EEE7728A615A5DB4785473F8F85F17AFB70CD62CA6E4CA0CE1BFA828114DC2A121AA7446B31465C9F7C442F2D70655D530598139F51CFC5F5406DED7F67FCEAA282A45374E3168B2CFF5596DF01FDFC2E3706525BAB4242A03096989CA9A740086CAECF0C3CB15EFAF750C84FE41DC9B6C61D051B79F6CDE48AB1554C3C7A822C3FECAA31E7716AA27D016EF50203010001";

    
    /**
     * ip adress assigned to end point(client)
     */
    private static final String IP_ADDRESS = "10.0.0.2";

    /** used for socket connection */
    private static final int PORT = 5000;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected VersionService versionService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ApplicationIdStore applicationIdStore;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected IdBlockStore idBlockStore;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ApplicationService appService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected EventDeliveryService eventDeliveryService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected MetricsService metricsService;

    /** Configure shared pool maximum size. */
    private int sharedThreadPoolSize = SHARED_THREAD_POOL_SIZE_DEFAULT;

    /** Maximum number of millis an event sink has to process an event. */
    private int maxEventTimeLimit = MAX_EVENT_TIME_LIMIT_DEFAULT;

    /** Enable queue performance check on shared pool. */
    private boolean sharedThreadPerformanceCheck = CALCULATE_PERFORMANCE_CHECK_DEFAULT;


    @Activate
    protected void activate() {
        registerApplication(CORE_APP_NAME);
        cfgService.registerProperties(getClass());
        System.out.println("Yuanhao's test works!!!");
        log.info("Yuanhao's test works!!! using log.info only use core build try");
        log.info("Yuanhao ONOS starting up on Java version {}, JVM version {}",
            System.getProperty("java.version"),
            System.getProperty("java.vm.version"));

        new Thread(() -> {
            try (ServerSocket serverSocket = new ServerSocket(5000, 50, InetAddress.getByName("0.0.0.0"))) {
                log.info("ONOS Socket Server started on all interfaces (0.0.0.0:5000)");

                while (true) {
                    Socket socket = serverSocket.accept();
                    log.info("Mininet h1 connected!");

                    BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                    PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()), true);

                    // 1st time: Server Read
                    log.info("[Server #1]");
                    String msg1 = input.readLine(); // randString1
                    log.info("[Server] Received #1: " + msg1);
                    if (msg1 == null) {
                        socket.close();
                    }

                    // parse randFromClient(randString1)
                    byte[] randFromClient = Base64.getDecoder().decode(msg1);
                    log.info("[Server]Received randFromClient: " + java.util.Arrays.toString(randFromClient));

                    // Parse my(Server) SK
                    byte[] privateKeyBytes = hexStringToByteArray(SERVER_PRIV_KEY_HEX);
                    PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA"); 
                    PrivateKey serverPrivateKey = keyFactory.generatePrivate(pkcs8KeySpec);

                    // Encript randString1 using my(server) SK
                    Cipher cipherEnc = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipherEnc.init(Cipher.ENCRYPT_MODE, serverPrivateKey);
                    byte[] encryptedByServerPriv = cipherEnc.doFinal(randFromClient);
                    // log.info("[Server] used PRIVATE key to encrypt -> " + bytesToHex(encryptedByServerPriv));
                    
                    // Generate randString2
                    byte[] randFromServer = generateRandomBytes(16);
                    log.info("[Server] generated random data = " + bytesToHex(randFromServer));

                    // 2nd time: Server Write
                    log.info("[Server #2]");
                    String randFromServerStr = Base64.getEncoder().encodeToString(randFromServer);
                    String encryptedByServerPrivStr = Base64.getEncoder().encodeToString(encryptedByServerPriv);
                    output.println(randFromServerStr + ',' + encryptedByServerPrivStr);
                    log.info("[Server] Sent #2 :" + randFromServerStr + ',' + encryptedByServerPrivStr);

                    // 3rd time: Server Read
                    log.info("[Server #3]");
                    String msg3 = input.readLine();
                    log.info("[Server] Received #3: " + msg3);
                    if (msg3 == null) {
                        socket.close();
                    }
                    byte[] encryptedByClientPriv = Base64.getDecoder().decode(msg3);
                    // Decription using Client's PK
                    byte[] publicKeyBytes  = hexStringToByteArray(CLIENT_PUBLIC_KEY_HEX);
                    X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKeyBytes);
                    PublicKey clientPublicKey = keyFactory.generatePublic(x509KeySpec);
                    Cipher cipherDec = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipherDec.init(Cipher.DECRYPT_MODE, clientPublicKey);
                    byte[] decryptedOnServer = cipherDec.doFinal(encryptedByClientPriv);
                    // System.out.println("Server used CLIENT's PUBLIC key to decrypt -> " + bytesToHex(decryptedOnServer));

                    // Verification
                    if (Arrays.equals(randFromServer, decryptedOnServer)) {
                        log.info("[Server] verification PASSED! Client indeed holds the private key.");
                    } else {
                        log.info("[Server] verification FAILED! Client does NOT has the private key.");
                    }

                    // 4th time: Server Write
                    log.info("[Server #4]");
                    output.println(encryptIPWithClientPK(IP_ADDRESS));
                    log.info("[Server] Sent #4");

                    log.info("[Server] Closing connection...");
                    socket.close();
                }
            } catch (Exception e) {
                log.error("Socket Server error", e);
            }
        }).start();
    }

    private String encryptIPWithClientPK(String ipAddress) {
        try {
            byte[] ipBytes = ipAddress.getBytes(java.nio.charset.StandardCharsets.UTF_8);

            // parse Client PK
            byte[] publicKeyBytes  = hexStringToByteArray(CLIENT_PUBLIC_KEY_HEX);
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA"); 
            PublicKey clientPublicKey = keyFactory.generatePublic(x509KeySpec);
    
            // Encription using Client PK
            Cipher cipherEnc = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipherEnc.init(Cipher.ENCRYPT_MODE, clientPublicKey);
            byte[] encryptedByClientPub = cipherEnc.doFinal(ipBytes);
            // log.info("[Server #4] used Client PUBLIC key to encrypt ip address -> " + bytesToHex(encryptedByClientPub));
    
            String ipAddressFromServerStr = Base64.getEncoder().encodeToString(encryptedByClientPub);
            // log.info("[Server #4] ipAddressFromServerStr " + ipAddressFromServerStr);
            return ipAddressFromServerStr;

        } catch (Exception e) {
            log.info("encryptIPWithClientPK error ipAddress {}", ipAddress, e);
        }
        return "";
    }

    private byte[] hexStringToByteArray(String s) {
        if ((s.length() % 2) != 0) {
            throw new IllegalArgumentException("Hex string length must be even.");
        }
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) (
                (Character.digit(s.charAt(i), 16) << 4)
                + Character.digit(s.charAt(i+1), 16)
            );
        }
        return data;
    }

    private byte[] generateRandomBytes(int length) throws NoSuchAlgorithmException {
        SecureRandom random = new SecureRandom(); 
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    private String bytesToHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    @Deactivate
    protected void deactivate() {
        cfgService.unregisterProperties(getClass(), false);
        SharedExecutors.shutdown();
        SharedScheduledExecutors.shutdown();
    }

    @Override
    public Version version() {
        checkPermission(APP_READ);
        return versionService.version();
    }

    @Override
    public Set<ApplicationId> getAppIds() {
        checkPermission(APP_READ);
        return applicationIdStore.getAppIds();
    }

    @Override
    public ApplicationId getAppId(Short id) {
        checkPermission(APP_READ);
        return applicationIdStore.getAppId(id);
    }

    @Override
    public ApplicationId getAppId(String name) {
        checkPermission(APP_READ);
        return applicationIdStore.getAppId(name);
    }

    @Override
    public ApplicationId registerApplication(String name) {
        checkPermission(APP_WRITE);
        checkNotNull(name, "Application ID cannot be null");
        return applicationIdStore.registerApplication(name);
    }

    @Override
    public ApplicationId registerApplication(String name, Runnable preDeactivate) {
        checkPermission(APP_WRITE);
        ApplicationId id = registerApplication(name);
        appService.registerDeactivateHook(id, preDeactivate);
        return id;
    }

    @Override
    public IdGenerator getIdGenerator(String topic) {
        checkPermission(APP_READ);
        IdBlockAllocator allocator = new StoreBasedIdBlockAllocator(topic, idBlockStore);
        return new BlockAllocatorBasedIdGenerator(allocator);
    }

    @Modified
    protected void modified(ComponentContext context) {
        Dictionary<?, ?> properties = context.getProperties();
        Integer poolSize = Tools.getIntegerProperty(properties, SHARED_THREAD_POOL_SIZE);

        if (poolSize != null && poolSize > 1) {
            sharedThreadPoolSize = poolSize;
            SharedExecutors.setPoolSize(sharedThreadPoolSize);
        } else if (poolSize != null) {
            log.warn("sharedThreadPoolSize must be greater than 1");
        }

        Integer timeLimit = Tools.getIntegerProperty(properties, MAX_EVENT_TIME_LIMIT);
        if (timeLimit != null && timeLimit >= 0) {
            maxEventTimeLimit = timeLimit;
            eventDeliveryService.setDispatchTimeLimit(maxEventTimeLimit);
        } else if (timeLimit != null) {
            log.warn("maxEventTimeLimit must be greater than or equal to 0");
        }

        Boolean performanceCheck = Tools.isPropertyEnabled(properties, CALCULATE_PERFORMANCE_CHECK);
        if (performanceCheck != null) {
            sharedThreadPerformanceCheck = performanceCheck;
            SharedExecutors.setMetricsService(sharedThreadPerformanceCheck ? metricsService : null);
        }

        log.info("Settings: sharedThreadPoolSize={}, maxEventTimeLimit={}, sharedThreadPerformanceCheck={}",
                 sharedThreadPoolSize, maxEventTimeLimit, sharedThreadPerformanceCheck);
    }
}
