package fri.vp;

import fri.isp.Agent;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Ed25519Signature {

    public static KeyPair gen() throws Exception {
        return null;
    }

    public static byte[] sign(PrivateKey key, byte[] message) throws Exception {
        return null;
    }

    public static boolean verify(PublicKey key, byte[] message, byte[] signature) throws Exception {
        return false;
    }

    public static void main(String[] args) throws Exception {
        final byte[] document = "We would like to sign this.".getBytes(StandardCharsets.UTF_8);

        final KeyPair key = gen();
        Files.write(Path.of("../ed25519.pk"), key.getPublic().getEncoded());
        Files.write(Path.of("../ed25519.sk"), key.getPrivate().getEncoded());

        final byte[] signature = sign(key.getPrivate(), document);
        System.out.println("Signature: " + Agent.hex(signature));
        Files.write(Path.of("../ed25519.sig"), signature);
        Files.write(Path.of("../ed25519.msg"), document);

        if (verify(key.getPublic(), document, signature)) {
            System.out.println("Valid signature.");
        } else {
            System.err.println("Invalid signature.");
        }
    }
}
