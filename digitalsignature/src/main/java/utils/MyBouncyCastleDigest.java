package utils;

import org.spongycastle.jcajce.provider.digest.MD2;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Description
 *
 * @author <a href="mailto:ricardo.vieira@xpand-it.com">RJSV</a>
 * @version $Revision : 1 $
 */

public class MyBouncyCastleDigest implements SignatureUtils.MyExternalDigest {

    public MyBouncyCastleDigest() {
    }

    public MessageDigest getMessageDigest(String hashAlgorithm) throws GeneralSecurityException {
        String oid = DigestAlgorithms.getAllowedDigests(hashAlgorithm);
        if (oid == null) {
            throw new NoSuchAlgorithmException(hashAlgorithm);
        } else if (oid.equals("1.2.840.113549.2.2")) {
            return new MD2.Digest();
        } else if (oid.equals("1.2.840.113549.2.5")) {
            return new org.spongycastle.jcajce.provider.digest.MD5.Digest();
        } else if (oid.equals("1.3.14.3.2.26")) {
            return new org.spongycastle.jcajce.provider.digest.SHA1.Digest();
        } else if (oid.equals("2.16.840.1.101.3.4.2.4")) {
            return new org.spongycastle.jcajce.provider.digest.SHA224.Digest();
        } else if (oid.equals("2.16.840.1.101.3.4.2.1")) {
            return new org.spongycastle.jcajce.provider.digest.SHA256.Digest();
        } else if (oid.equals("2.16.840.1.101.3.4.2.2")) {
            return new org.spongycastle.jcajce.provider.digest.SHA384.Digest();
        } else if (oid.equals("2.16.840.1.101.3.4.2.3")) {
            return new org.spongycastle.jcajce.provider.digest.SHA512.Digest();
        } else if (oid.equals("1.3.36.3.2.2")) {
            return new org.spongycastle.jcajce.provider.digest.RIPEMD128.Digest();
        } else if (oid.equals("1.3.36.3.2.1")) {
            return new org.spongycastle.jcajce.provider.digest.RIPEMD160.Digest();
        } else if (oid.equals("1.3.36.3.2.3")) {
            return new org.spongycastle.jcajce.provider.digest.RIPEMD256.Digest();
        } else if (oid.equals("1.2.643.2.2.9")) {
            return new org.spongycastle.jcajce.provider.digest.GOST3411.Digest();
        } else {
            throw new NoSuchAlgorithmException(hashAlgorithm);
        }
    }
}