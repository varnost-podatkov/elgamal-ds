package fri.vp;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class ECIESExample {
    public record Ciphertext(byte[] pk, byte[] iv, byte[] ct) {
    }

    public static KeyPair gen() throws Exception {
        return null;
    }

    public static Ciphertext encrypt(PublicKey pk, byte[] plaintext) throws Exception {
        return new Ciphertext(null, null, null);
    }

    public static byte[] decrypt(PrivateKey sk, byte[] pk, byte[] iv, byte[] ct) throws Exception {
        return null;
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
