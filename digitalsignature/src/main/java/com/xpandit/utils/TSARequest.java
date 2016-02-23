package com.xpandit.utils;

import android.util.Base64;
import android.util.Log;

import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.TSAClient;

import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.HttpsURLConnection;

/**
 * Description
 *
 * @author <a href="mailto:ricardo.vieira@xpand-it.com">RJSV</a>
 * @version $Revision : 1 $
 */

public class TSARequest implements TSAClient {

    // region Computation Elements
    protected String tsaURL;
    protected String tsaUsername;
    protected String tsaPassword;
    protected String tsaOid;
    protected int tokenSizeEstimate;
    protected String digestAlgorithm;
    private static final String defaultAlgorithm = "SHA-256";
    private static String TAG = TSARequest.class.getSimpleName();
    // endregion

    // region Constructors
    public TSARequest(String url) {
        this(url, null, null, null, 4096, defaultAlgorithm);
    }

    public TSARequest(String url, String username, String password) {
        this(url, username, password, null, 4096, defaultAlgorithm);
    }

    public TSARequest(String url, String username, String password, String oid, int tokSzEstimate, String digestAlgorithm) {
        this.tsaURL = url;
        this.tsaUsername = username;
        this.tsaPassword = password;
        this.tsaOid = oid;
        this.tokenSizeEstimate = tokSzEstimate;
        this.digestAlgorithm = digestAlgorithm;
    }
    // endregion

    // region Interface Methods
    public int getTokenSizeEstimate() {
        return this.tokenSizeEstimate;
    }

    public MessageDigest getMessageDigest() throws GeneralSecurityException {
        return MessageDigest.getInstance("SHA-1");
    }

    public byte[] getTimeStampToken(PdfPKCS7 pdfPKCS7, byte[] digest) throws NoSuchAlgorithmException, UnsupportedEncodingException, TSPException {

        TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
        tsqGenerator.setCertReq(true);
        tsqGenerator.setReqPolicy(tsaOid);
        TimeStampRequest tsReq = tsqGenerator.generate(TSPAlgorithms.SHA1, digest, BigInteger.valueOf(100));
        byte[] respBytes;
        try {
            byte[] requestBytes = tsReq.getEncoded();
            URL url = new URL(tsaURL);
            HttpsURLConnection tsaConnection = (HttpsURLConnection) url.openConnection();
            String user_pass = Base64.encodeToString((tsaUsername + ":" + tsaPassword).getBytes(), 0);
            tsaConnection.setRequestProperty("Authorization", "Basic " + user_pass);
            tsaConnection.setDoInput(true);
            tsaConnection.setDoOutput(true);
            tsaConnection.setUseCaches(false);
            tsaConnection.setRequestProperty("Content-Type", "application/timestamp-query");
            tsaConnection.setRequestProperty("Content-Transfer-Encoding", "binary");
            OutputStream out = tsaConnection.getOutputStream();
            out.write(requestBytes);
            out.close();
            InputStream inp = tsaConnection.getInputStream();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inp.read(buffer, 0, buffer.length)) >= 0) {
                baos.write(buffer, 0, bytesRead);
            }
            respBytes = baos.toByteArray();
            String encoding = tsaConnection.getContentEncoding();
            if (encoding != null && encoding.equalsIgnoreCase("base64")) {
                respBytes = Base64.decode(new String(respBytes), 0);
            }

            if (respBytes == null) {
                String error = "Error: Impossible to get TSA response";
                Log.e(TAG, error);
            }
            TimeStampResponse tsRes = new TimeStampResponse(respBytes);

            tsRes.validate(tsReq);
            PKIFailureInfo failure = tsRes.getFailInfo();
            int value = (failure == null) ? 0 : failure.intValue();
            if (value != 0) {
                String error = "Error: Invalid TSA response (" + tsRes.getStatusString() + ")";
                System.out.println(error);
                return null;
            }
            TimeStampToken myTSToken = tsRes.getTimeStampToken();
            if (myTSToken == null) {
                String error = "Error: Invalid TSA response (NULL)";
                System.out.println(error);
                return null;
            }
            return myTSToken.getEncoded();
        } catch (IOException | TSPException e) {
            System.out.println(e.getMessage());
        }
        return null;
    }
    // endregion
    
}
