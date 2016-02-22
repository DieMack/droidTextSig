package utils;

import java.security.GeneralSecurityException;

/**
 * Description
 *
 * @author <a href="mailto:ricardo.vieira@xpand-it.com">RJSV</a>
 * @version $Revision : 1 $
 */

/**
 * PtIdCard implementation of the MyExternalSignature Interface
 */
public class PtIdSignature implements SignatureUtils.MyExternalSignature {

    private String encryptionAlgorithm;
    private String hashAlgorithm;


    public PtIdSignature(String hashAlgorithm, String encryptionAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
        this.encryptionAlgorithm = encryptionAlgorithm;
    }

    public String getEncryptionAlgorithm() {
        return this.encryptionAlgorithm;
    }

    @Override
    public byte[] sign(byte[] var1) throws GeneralSecurityException {
        return new byte[0];
    }

    public String getHashAlgorithm() {
        return this.hashAlgorithm;
    }

}