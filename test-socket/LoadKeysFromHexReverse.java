import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;

public class LoadKeysFromHexReverse {



    /**
     * Client Private Key
     */
    private static final String CLIENT_PRIV_KEY_HEX = "308204BE020100300D06092A864886F70D0101010500048204A8308204A4020100028201010084020B2CFD1BE4E3050555F7A4747A30BF7349D5D5D8767BC5B30FD624916E264217F97599FF1B5F09AEE97E80F8851D5DA61EED9D8A4CBE67CBB6389C59874457D83B23BBC4D92EA7F3303E0BA5AA69A03CBF6639DEE6ECA1A73C47BD3D4998EE0332836ED5DEF91A0C01352AAEE6458D05FB1EEE7728A615A5DB4785473F8F85F17AFB70CD62CA6E4CA0CE1BFA828114DC2A121AA7446B31465C9F7C442F2D70655D530598139F51CFC5F5406DED7F67FCEAA282A45374E3168B2CFF5596DF01FDFC2E3706525BAB4242A03096989CA9A740086CAECF0C3CB15EFAF750C84FE41DC9B6C61D051B79F6CDE48AB1554C3C7A822C3FECAA31E7716AA27D016EF50203010001028201003C920F7CB21AB578715A546ACFDBDE213607794E93D3C1F1E2F1D98761BA15379AC61361A1AA8B6D9D2CD3D886E701754AFE295CD017A04511AD484C4B794CF6CFF3D896F9D645ED0185359292978E4CEF0850AE604965DE18027B47538EA691744CA545E77A5CD821DA764765F16099732ED65E07FF46F88620573046F83D323DF38902F16FE4A3307221430BFE3BBFA9B94FCDEBBFC74C500E0D2531F0CFED0E652878FE4CBE9EA5FE19F8584818A31AEDAAC1B2C015C476FC30E6861BEA9A521CB64953DA14EE97409B0B86FC55ACA04B5A0EDD6DEF55736061DECB4157CB1E53E46953BE4DBC1D5E8A838167FF3E4BE70F67529449005E3F20AF15F4A8B502818100BDB461D3BE5059FDD8CA21C8DEBC81337492E3AD337CA02A141645E2784E0B56D945E9AB0EBF9EDB3CCCF1DA3BD8F51055D680DEE39F2F2D72F9846A76228F0773DC8F48CBC02034D7257C6AAF80FDCB85F948F5AD506C3181103074FA6F783844846831D9A36406AB22E33C276F22816284F7E133C125F84F8C5557903FCA0B02818100B223ECD2A58CBD959F47B93FC8406AA115DA816377D33EAEC950169311FDBC21B99746A77494393F3629DC9F99A083D815B187A01305C8C87DCE3659DDC1CEC6AF3AC4073DA1AC031F68EC13139F7EE70D75D7DCAF459F9132D0CD6977B2DD504714361DFD4F0F2966829984A8981DD03B01A4B2A2D923528490D1FC51304AFF02818008CE30A4457731562913E8D18C152FE2158D23E84C3582B1B150FF596DC021A29C5F34636E41D2BBD66CA4E53E55E9BA2261DC857C074D874C88EC6E8CA13A065C88665638AEE84FCB94BFDBABDDCEE9FD83FEB0F8A47D01273E7B2152E68DABFEF22E6BF1F0359A61A332ECFDDF98B86CBC434D3EBBBE697237CF564B29CAD502818100896A00F2F4D53E213EBEDAFD82817E3F4856475CED3FBCA8A38DEDFC00F2D3BEC82513517532297EC34F436AB1DD0A171394E063F08893BB64A03F78CF01037A6C0D4ECDAF13195747516E59C0D755D2F1A527A08A6B908D36BFAED45E8B5100EDF37F535EE52F72E62A7435CABF9CAFD5F48C9167E14BC8098E950CA7AC330D02818100B71D737298796619388CFC0CA12E5A2FB7818756BEDE211308F1F887C23E76E2D127B5242E6E69F6CA3D7F5257E6B559DD6DCD4B4C90335D974C730E9D98590D0CF897C91843D49A0C68600299CCD5D870430866D484D1C8C9E8919002ED08AB557C7030727AA0E97510FC7169A0CA893408D9ED8C51EE537177DCEBAE87B82F";
    
    /**
     * Client Public Key
     */
    private static final String CLIENT_PUBLIC_KEY_HEX = "30820122300D06092A864886F70D01010105000382010F003082010A028201010084020B2CFD1BE4E3050555F7A4747A30BF7349D5D5D8767BC5B30FD624916E264217F97599FF1B5F09AEE97E80F8851D5DA61EED9D8A4CBE67CBB6389C59874457D83B23BBC4D92EA7F3303E0BA5AA69A03CBF6639DEE6ECA1A73C47BD3D4998EE0332836ED5DEF91A0C01352AAEE6458D05FB1EEE7728A615A5DB4785473F8F85F17AFB70CD62CA6E4CA0CE1BFA828114DC2A121AA7446B31465C9F7C442F2D70655D530598139F51CFC5F5406DED7F67FCEAA282A45374E3168B2CFF5596DF01FDFC2E3706525BAB4242A03096989CA9A740086CAECF0C3CB15EFAF750C84FE41DC9B6C61D051B79F6CDE48AB1554C3C7A822C3FECAA31E7716AA27D016EF50203010001";


    public static void main(String[] args) throws Exception {
        // 1. parse SK
        byte[] privateKeyBytes = hexStringToByteArray(CLIENT_PRIV_KEY_HEX);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); 
        PrivateKey clientPrivateKey = keyFactory.generatePrivate(pkcs8KeySpec);

        // 2. parse PK
        byte[] publicKeyBytes  = hexStringToByteArray(CLIENT_PUBLIC_KEY_HEX);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey clientPublicKey = keyFactory.generatePublic(x509KeySpec);

        System.out.println("Private Key Algorithm: " + clientPrivateKey.getAlgorithm() 
                           + ", format: " + clientPrivateKey.getFormat());
        System.out.println("Public  Key Algorithm: " + clientPublicKey.getAlgorithm() 
                           + ", format: " + clientPublicKey.getFormat());

        // 3. generate randString
        // byte[] randFromServer = generateRandomBytes(16);
        byte[] randFromServer = "192.168.0.1".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("Server generated random data = " + bytesToHex(randFromServer));

        // Encription using Client PK
        Cipher cipherEnc = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipherEnc.init(Cipher.ENCRYPT_MODE, clientPublicKey);
        byte[] encryptedByClientPub = cipherEnc.doFinal(randFromServer);
        System.out.println("Client used PUBLIC key to encrypt -> " + bytesToHex(encryptedByClientPub));

        // Decription using Client SK
        Cipher cipherDec = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipherDec.init(Cipher.DECRYPT_MODE, clientPrivateKey);
        byte[] decryptedOnServer = cipherDec.doFinal(encryptedByClientPub);
        System.out.println("Server used CLIENT's PRIVATE key to decrypt -> " + bytesToHex(decryptedOnServer));

        // verify results
        if (Arrays.equals(randFromServer, decryptedOnServer)) {
            System.out.println("Server verification PASSED! (PubKey encrypt -> PrivKey decrypt success)");
        } else {
            System.out.println("Server verification FAILED!");
        }

        // String ipAddressFromServerStr = Base64.getEncoder().encodeToString(decryptedOnServer);
        String decryptedIp = new String(decryptedOnServer, java.nio.charset.StandardCharsets.UTF_8);

        System.out.println("Ip address:" + decryptedIp);

    }
    

    private static byte[] hexStringToByteArray(String s) {
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

    private static byte[] generateRandomBytes(int length) throws NoSuchAlgorithmException {
        SecureRandom random = new SecureRandom(); 
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    private static String bytesToHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
