package com.xpandit.utils;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

/**
 * Description
 *
 * @author <a href="mailto:ricardo.vieira@xpand-it.com">RJSV</a>
 * @version $Revision : 1 $
 */

public class SignatureUtils {


    public interface MyExternalDigest {
        MessageDigest getMessageDigest(String var1) throws GeneralSecurityException;
    }

    public interface MyExternalSignature {

        String getHashAlgorithm();

        String getEncryptionAlgorithm();

        byte[] sign(byte[] var1) throws GeneralSecurityException;
    }

}

