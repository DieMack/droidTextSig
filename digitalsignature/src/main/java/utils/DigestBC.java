package utils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.GeneralSecurityException;
import java.security.Security;

public class DigestBC extends DigestDefault {

    public static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    protected DigestBC(byte[] msgBytes, String algorithm) throws GeneralSecurityException {
        super(msgBytes, algorithm, PROVIDER.getName());
    }

    public static DigestBC getInstance(byte[] msgBytes, String algorithm) throws GeneralSecurityException {
        return new DigestBC(msgBytes, algorithm);
    }

}
