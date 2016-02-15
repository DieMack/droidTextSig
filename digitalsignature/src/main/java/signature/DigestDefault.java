package signature;

import android.util.Log;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class DigestDefault {

    final static String TAG = DigestDefault.class.getSimpleName();

    protected static final byte[] SHA256_AID = {(byte) 0x30, (byte) 0x31,
            (byte) 0x30, (byte) 0x0d, (byte) 0x06, (byte) 0x09, (byte) 0x60,
            (byte) 0x86, (byte) 0x48, (byte) 0x01, (byte) 0x65, (byte) 0x03,
            (byte) 0x04, (byte) 0x02, (byte) 0x01, (byte) 0x05, (byte) 0x00,
            (byte) 0x04, (byte) 0x20};

    protected static final byte[] SHA1_AID = {(byte) 0x30, (byte) 0x21,
            (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x05, (byte) 0x2b,
            (byte) 0x0e, (byte) 0x03, (byte) 0x02, (byte) 0x1a, (byte) 0x05,
            (byte) 0x00, (byte) 0x04, (byte) 0x14};
    protected static byte[] digestWithAID;
    protected byte[] digest;
    protected MessageDigest md;

    protected DigestDefault(byte[] msgBytes, String algorithm, String provider) throws GeneralSecurityException {
        if (provider == null) {
            md = MessageDigest.getInstance(algorithm);
        } else {
            md = MessageDigest.getInstance(algorithm, provider);
        }
        digest = md.digest(msgBytes);
    }

    public static DigestDefault getInstance(byte[] msgBytes, String algorithm, String provider) throws GeneralSecurityException {
        return new DigestDefault(msgBytes, algorithm, provider);
    }

    public static byte[] getDigestWithSHA256AID(byte[] msgBytes, String algorithm) throws GeneralSecurityException {
        DigestDefault app = DigestBC.getInstance(msgBytes, algorithm);
        digestWithAID = new byte[51];
        System.arraycopy(SHA256_AID, 0, digestWithAID, 0, 19);
        System.arraycopy(app.getDigest(), 0, digestWithAID, 19, app.getDigestSize());

        return digestWithAID;
    }

    public byte[] getDigest() {
        return digest;
    }

    public int getDigestSize() {
        return digest.length;
    }

    public static byte[] getDigest(byte[] msgBytes, String algorithm) throws GeneralSecurityException {
        DigestDefault app = DigestBC.getInstance(msgBytes, algorithm);
        digestWithAID = new byte[34];
        digestWithAID[0] = (byte) 0x90;
        digestWithAID[1] = (byte) 0x20;//SHA-256 produces msg digest of 32 lenght(32 = 0x20)
        System.arraycopy(app.getDigest(), 0, digestWithAID, 2, app.getDigestSize());
        return digestWithAID;
    }

    public static void showTest(byte[] msgBytes, String algorithm) throws GeneralSecurityException {
        try {
            DigestDefault app = DigestBC.getInstance(msgBytes, algorithm);
            Log.d(TAG, "Digest using " + algorithm + ": " + app.getDigestSize());
            Log.d(TAG, "Digest: " + app.getDigestAsHexString());
            Log.d(TAG, "Is the password 'password'? " + app.checkPassword("password"));
            Log.d(TAG, "Is the password 'secret'? " + app.checkPassword("secret"));
        } catch (NoSuchAlgorithmException e) {
            Log.d(TAG, e.getMessage());
        }
    }

    public String getDigestAsHexString() {
        return new BigInteger(1, digest).toString(16);
    }

    public boolean checkPassword(String password) {
        return Arrays.equals(digest, md.digest(password.getBytes()));
    }

}
