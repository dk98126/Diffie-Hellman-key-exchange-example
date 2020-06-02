package example;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/*
 * Обмен ключами Диффи-Хеллмана между двумя сторонами.
 */
public class DHKeyAgreement2 {
    private DHKeyAgreement2() {
    }

    public static void main(String[] args) throws Exception {
        //Алиса создает свою пару ключей ДХ с длиной ключа 2048.
        System.out.println("АЛИСА: Генерация пары ключей ДХ ...");
        KeyPairGenerator aliceKeyPairGen = KeyPairGenerator.getInstance("DH");
        aliceKeyPairGen.initialize(2048);
        KeyPair aliceKeyPair = aliceKeyPairGen.generateKeyPair();

        //Алиса создает и инициализирует ее объект ДХ согласия.
        System.out.println("АЛИСА: инициализация ...");
        KeyAgreement aliceKeyAgreement = KeyAgreement.getInstance("DH");
        aliceKeyAgreement.init(aliceKeyPair.getPrivate());

        //Алиса кодирует (не шифрует!) ее публичный ключ и посылает его бобу.
        byte[] alicePubKeyEnc = aliceKeyPair.getPublic().getEncoded();

        /*
         * Теперь перейдем к Бобу. Боб получил публичный ключ алисы в закодированном формате.
         * Он создает объект этого публичного ключа из закодированного ключного материала.
         */
        KeyFactory bobKeyFactory = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(alicePubKeyEnc);

        PublicKey alicePublicKey = bobKeyFactory.generatePublic(x509EncodedKeySpec);

        /*
         * Боб получает ДХ параметры, связанные с публичным ключом Алисы.
         * Он должен использовать те же параметры, когда он генерирует свою пару ключей.
         */
        DHParameterSpec dhParameterSpecFromAlicePublicKey = ((DHPublicKey)alicePublicKey).getParams();

        //Боб создает свою пару ключей.
        System.out.println("БОБ: создание ДХ пары ключей ...");
        KeyPairGenerator bobKeyPairGen = KeyPairGenerator.getInstance("DH");
        bobKeyPairGen.initialize(dhParameterSpecFromAlicePublicKey);
        KeyPair bobKeyPair = bobKeyPairGen.generateKeyPair();

        //Боб создает и инициализирует его объект ДХ договоренности.
        System.out.println("БОБ: инициализация");
        KeyAgreement bobKeyAgreement = KeyAgreement.getInstance("DH");
        bobKeyAgreement.init(bobKeyPair.getPrivate());

        //Боб кодирует (не шифрует!) свой публичный ключ и отправляет его Алисе.
        byte[] bobPubKeyEnc = bobKeyPair.getPublic().getEncoded();

        /*
         * Алиса использует публичный ключ Боба в первую (и единственную) фазу ее версии ДХ протокола.
         * Перед тем как она сделает это, она должна создать объект публичного ключа Боба из закодированного материала.
         */
        KeyFactory aliceKeyFac = KeyFactory.getInstance("DH");
        x509EncodedKeySpec = new X509EncodedKeySpec(bobPubKeyEnc);
        PublicKey bobPubKey = aliceKeyFac.generatePublic(x509EncodedKeySpec);
        System.out.println("АЛИСА: выполняется ФАЗА_1 ...");
        aliceKeyAgreement.doPhase(bobPubKey, true);

        /*
         * Боб использует публичный ключ Алисы в первую (и единственную) фазу его версии ДХ протокола.
         */
        System.out.println("БОБ: выполняется ФАЗА_1 ...");
        bobKeyAgreement.doPhase(alicePublicKey, true);

        /*
         * На этом этапе Алиса и Боб завершили выполнение протокола ДХ.
         * Оба генерируют один и тот же общий секрет.
         */
        byte[] aliceSharedSecret = aliceKeyAgreement.generateSecret();
        int aliceLen = aliceSharedSecret.length;
        byte[] bobSharedSecret = new byte[aliceLen];
        int bobLen = bobKeyAgreement.generateSecret(bobSharedSecret, 0);

        System.out.println("Секрет Алисы: " + toHexString(aliceSharedSecret));
        System.out.println("Секрет Боба: " + toHexString(bobSharedSecret));
        if (!Arrays.equals(aliceSharedSecret, bobSharedSecret)) {
            throw new Exception("Общие секреты различны");
        }
        System.out.println("Общие секреты одинаковы");

        System.out.println("Используем общий секрет как объект SecretKey ...");
        SecretKeySpec bobAesKey = new SecretKeySpec(bobSharedSecret, 0, 16, "AES");
        SecretKeySpec aliceAesKey = new SecretKeySpec(aliceSharedSecret, 0, 16, "AES");

        Cipher bobCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        bobCipher.init(Cipher.ENCRYPT_MODE, bobAesKey);
        byte[] clearText = "Это просто пример".getBytes();
        byte[] cipherText = bobCipher.doFinal(clearText);

        //Получаем параметры при шифровании, чтобы отправить Алисе
        byte[] encodedParams = bobCipher.getParameters().getEncoded();

        /*
         * Алиса расшифровывает, используя AES в режиме CBC
         */
        AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES");
        aesParams.init(encodedParams);
        Cipher aliceCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aliceCipher.init(Cipher.DECRYPT_MODE, aliceAesKey, aesParams);
        byte[] recovered = aliceCipher.doFinal(cipherText);
        if (!Arrays.equals(clearText, recovered)) {
            throw new Exception("AES в режиме CBC неправильно расшифровал текст");
        }
        System.out.println("AES in CBC, расшифрованный текст совпадает с исходным");
    }

    /*
     * Преобразует байт в шестнадцатеричное число и записывает в предоставленный буфер
     */
    private static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }

    /*
     * Преобразует байтовый массив в шестнадцатеричную строку
     */
    private static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();
        int len = block.length;
        for (int i = 0; i < len; i++) {
            byte2hex(block[i], buf);
            if (i < len-1) {
                buf.append(":");
            }
        }
        return buf.toString();
    }
}
