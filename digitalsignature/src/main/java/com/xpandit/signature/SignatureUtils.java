package com.xpandit.signature;

import android.graphics.Bitmap;

import com.lowagie.text.DocumentException;
import com.lowagie.text.Image;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.PdfDate;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfSignature;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import com.lowagie.text.pdf.PdfStamper;
import com.lowagie.text.pdf.PdfString;
import com.lowagie.text.pdf.TSAClient;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Set;

import utils.FileUtils;

/**
 * Description
 *
 * @author <a href="mailto:ricardo.vieira@xpand-it.com">RJSV</a>
 * @version $Revision : 1 $
 */

public class SignatureUtils {

    /**
     * getFormFieldPositions - Return the SignatureData for a given signatureName
     *
     * @param fileName
     * @param signatureName
     * @return SignatureData -
     * @throws IOException
     */
    public static SignatureData getFormFieldPositions(String fileName, String signatureName) throws IOException {
        int page = -1;
        float pageWidth = 0, pageHeight = 0, llx = 0, lly = 0, urx = 0, ury = 0;
        // Create a signature_activity to extract info
        PdfReader reader = new PdfReader(fileName);
        // Get the fields from the signature_activity (read-only!!!)
        AcroFields form = reader.getAcroFields();
        // Loop over the fields and get info about them
        Set<String> fields = form.getFields().keySet();

        for (String key : fields) {
            switch (form.getFieldType(key)) {
                case AcroFields.FIELD_TYPE_SIGNATURE:
                    if (form.getFieldPositions(signatureName).length > 0) {
                        float[] sigData = form.getFieldPositions(signatureName);
                        page = (int) sigData[0];
                        llx = sigData[1];
                        lly = sigData[2];
                        urx = sigData[3];
                        ury = sigData[4];
                        Rectangle rect = reader.getPageSize(page);
                        pageWidth = rect.getWidth();
                        pageHeight = rect.getHeight();
                    } else {
                        return null;
                    }
                    break;
                default:
                    break;
            }
        }
        reader.close();
        SignatureData sd = new SignatureData();
        sd.setSignatureName(signatureName);
        sd.setPage(page);
        sd.setPageWidth((int) pageWidth);
        sd.setPageHeight((int) pageHeight);
        sd.setLeft(llx);
        sd.setDown(lly);
        sd.setRight(urx);
        sd.setUp(ury);

        return sd;
    }

    /**
     * @param fileSource       - The input file used that is going to be signed
     * @param fileDestination  - The output file of the signing operation
     * @param keyStore         - The keystore containing the Private Key file
     * @param keyStorePassword - The Private key
     * @param tsaClient        - The Timestamp Client that is used to timestamp the operation. If null, the hour of the clock will be used
     * @param signatureData    - The Signature Data object that contains all relevant information regarding the signature
     * @param signatureImage   - The Bitmap of the handwritten (or not) generated bitmap. If null, wont be included on the signature
     * @return
     */
    public static SignatureResponse signPdf(String fileSource, String fileDestination, InputStream keyStore, char[] keyStorePassword, TSAClient tsaClient, SignatureData signatureData, Bitmap signatureImage) {
        try {
            BouncyCastleProvider provider = new BouncyCastleProvider();
            Security.addProvider(provider);
            KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
            ks.load(keyStore, keyStorePassword);
            String alias = ks.aliases().nextElement();
            PrivateKey pk = (PrivateKey) ks.getKey(alias, keyStorePassword);
            Certificate[] chain = ks.getCertificateChain(alias);

            if (!FileUtils.fileExists(fileSource)) {
                return SignatureResponse.FILE_NOT_EXIST;
            }
            PdfReader reader = new PdfReader(fileSource);
            FileOutputStream os = new FileOutputStream(String.format(fileDestination, 1));
            PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');

            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
            if (signatureImage != null) {
                ByteArrayOutputStream stream = new ByteArrayOutputStream();
                signatureImage.compress(Bitmap.CompressFormat.PNG, 100, stream);
                Image image = Image.getInstance(stream.toByteArray());
                appearance.setImage(image);
            }
            appearance.setLayer2Text("");
            appearance.setLayer4Text("");
            appearance.setAcro6Layers(true);
            appearance.setVisibleSignature(signatureData.getSignatureName());
            appearance.setCrypto(pk, chain, null, PdfSignatureAppearance.WINCER_SIGNED);

            PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, new PdfName("adbe.pkcs7.detached"));
            dic.setContact(signatureData.getAuthor());
            dic.setLocation(signatureData.getLocation());
            dic.setReason(signatureData.getReason());
            dic.setDate(new PdfDate());
            appearance.setCryptoDictionary(dic);

            int contentEstimated = 15000;
            HashMap<PdfName, Integer> exc = new HashMap<>();
            exc.put(PdfName.CONTENTS, contentEstimated * 2 + 2);
            appearance.preClose(exc);
            InputStream data = appearance.getRangeStream();
            MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
            byte buf[] = new byte[8192];
            int n;
            while ((n = data.read(buf)) > 0) {
                messageDigest.update(buf, 0, n);
            }
            byte[] hash = messageDigest.digest();
            Calendar cal = Calendar.getInstance();
            byte[] ocsp = null;
            PdfPKCS7 sgn = new PdfPKCS7(pk, chain, null, "SHA1", null, false);
            byte sh[] = sgn.getAuthenticatedAttributeBytes(hash, cal, ocsp);
            sgn.update(sh, 0, sh.length);
            byte[] encodedSig;
            try {
                encodedSig = sgn.getEncodedPKCS7(hash, cal, tsaClient, ocsp);
            } catch (Exception e){
                e.printStackTrace();
                return SignatureResponse.TSA_RESPONSE_ERROR;
            }
            if (encodedSig!=null && (contentEstimated + 2 < encodedSig.length)) {
                return SignatureResponse.NOT_ENOUGH_SPACE;
            }
            byte[] paddedSig = new byte[contentEstimated];
            System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length);
            PdfDictionary dic2 = new PdfDictionary();
            dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
            appearance.close(dic2);
        } catch (Exception e) {
            e.printStackTrace();
            return SignatureResponse.FAILURE;
        }
        return SignatureResponse.SUCCESS;
    }

}
