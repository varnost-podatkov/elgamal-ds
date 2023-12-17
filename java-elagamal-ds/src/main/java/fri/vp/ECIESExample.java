package fri.vp;

import fri.isp.Agent;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

public class ECIESExample {
    public static KeyPair gen() throws Exception {
        return KeyPairGenerator.getInstance("X25519").generateKeyPair();
    }

    public record Ciphertext(byte[] pk, byte[] iv, byte[] ct) {
    }

    public static Ciphertext encrypt(PublicKey pk, byte[] plaintext) throws Exception {
        final KeyPair ephemeralKey = gen();

        final KeyAgreement ka = KeyAgreement.getInstance("XDH");
        ka.init(ephemeralKey.getPrivate());
        ka.doPhase(pk, true);

        final MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(ephemeralKey.getPublic().getEncoded());
        sha.update(ka.generateSecret());
        final byte[] sharedBytes = sha.digest();

        final SecretKeySpec aesKey = new SecretKeySpec(sharedBytes, "ChaCha20");

        final Cipher gcm = Cipher.getInstance("ChaCha20-Poly1305");
        gcm.init(Cipher.ENCRYPT_MODE, aesKey);
        final byte[] ct = gcm.doFinal(plaintext);

        return new Ciphertext(ephemeralKey.getPublic().getEncoded(), gcm.getIV(), ct);
    }

    public static byte[] decrypt(PrivateKey sk, byte[] pk, byte[] iv, byte[] ct) throws Exception {
        final PublicKey epk = KeyFactory.getInstance("XDH").generatePublic(new X509EncodedKeySpec(pk));

        final KeyAgreement ka = KeyAgreement.getInstance("XDH");
        ka.init(sk);
        ka.doPhase(epk, true);

        final MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(pk);
        sha.update(ka.generateSecret());
        final byte[] sharedBytes = sha.digest();

        final SecretKeySpec aesKey = new SecretKeySpec(sharedBytes, "ChaCha20");

        final Cipher gcm = Cipher.getInstance("ChaCha20-Poly1305");
        gcm.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        return gcm.doFinal(ct);
    }

    public static void main(String[] args) throws Exception {
        final String message = "A test message.";
        final byte[] pt = message.getBytes(StandardCharsets.UTF_8);

        System.out.println("Message: " + message);
        System.out.println("PT: " + Agent.hex(pt));

        final KeyPair borKP = gen();

        Files.write(Path.of("../bor.pk"), borKP.getPublic().getEncoded());

//        final byte[] bytes = Files.readAllBytes(Path.of("../data/phonebook.bin"));
//        Files.write(Path.of("../fernet-java.key"), keyJava);

        final Ciphertext ct = encrypt(borKP.getPublic(), pt);

        System.out.println("PK: " + Agent.hex(ct.pk));
        System.out.println("CT: " + Agent.hex(ct.ct));
        System.out.println("IV: " + Agent.hex(ct.iv));

        final byte[] dt = decrypt(borKP.getPrivate(), ct.pk, ct.iv, ct.ct);
        System.out.println(new String(dt, StandardCharsets.UTF_8));

    }
}
