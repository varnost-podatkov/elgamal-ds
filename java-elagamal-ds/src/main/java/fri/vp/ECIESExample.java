package fri.vp;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;

public class ECIESExample {
    public record Ciphertext(byte[] pk, byte[] iv, byte[] ct) {
    }

    public static KeyPair gen() throws Exception {
        return KeyPairGenerator.getInstance("X25519").generateKeyPair();
//        return null;
    }

    public static Ciphertext encrypt(PublicKey pk, byte[] plaintext) throws Exception {
        final KeyPair tempKey = gen();

        final KeyAgreement ka = KeyAgreement.getInstance("XDH");
        ka.init(tempKey.getPrivate());
        ka.doPhase(pk, true);
        final MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(tempKey.getPublic().getEncoded());
        sha.update(ka.generateSecret());
        final SecretKeySpec key = new SecretKeySpec(sha.digest(), "ChaCha20-Poly1305");

        final Cipher chacha = Cipher.getInstance("ChaCha20-Poly1305");
        chacha.init(Cipher.ENCRYPT_MODE, key);

        return new Ciphertext(tempKey.getPublic().getEncoded(), chacha.getIV(), chacha.doFinal(plaintext));
//        return null;
    }

    public static byte[] decrypt(PrivateKey sk, byte[] pk, byte[] iv, byte[] ct) throws Exception {
        final KeyAgreement ka = KeyAgreement.getInstance("XDH");
        ka.init(sk);

        final XECPublicKey senderPK = (XECPublicKey) KeyFactory.getInstance("X25519").generatePublic(new X509EncodedKeySpec(pk));
        ka.doPhase(senderPK, true);

        final MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(senderPK.getEncoded());
        sha.update(ka.generateSecret());
        final SecretKeySpec key = new SecretKeySpec(sha.digest(), "ChaCha20-Poly1305");

        final Cipher chacha = Cipher.getInstance("ChaCha20-Poly1305");
        chacha.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        return chacha.doFinal(ct);
//        return null;
    }

    public static void main(String[] args) throws Exception {
        final String message = "A test message.";
        final byte[] pt = message.getBytes(StandardCharsets.UTF_8);

        final KeyPair borKP = gen();

        Files.write(Path.of("../ecies.pk"), borKP.getPublic().getEncoded());
        Files.write(Path.of("../ecies.sk"), borKP.getPrivate().getEncoded());
        Files.write(Path.of("../ecies.msg"), pt);

        final Ciphertext ct = encrypt(borKP.getPublic(), pt);
        Files.write(Path.of("../ecies.ct"),
                ByteBuffer.allocate(ct.pk.length + ct.iv.length + ct.ct.length)
                        .put(ct.pk).put(ct.iv).put(ct.ct).array());

        final byte[] dt = decrypt(borKP.getPrivate(), ct.pk, ct.iv, ct.ct);
        System.out.println(new String(dt, StandardCharsets.UTF_8));
    }
}
