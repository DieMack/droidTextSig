package com.xpandit.signature;

import android.graphics.Bitmap;
import android.os.AsyncTask;
import android.util.Log;

import com.lowagie.text.Chunk;
import com.lowagie.text.DocumentException;
import com.lowagie.text.Font;
import com.lowagie.text.Image;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.ColumnText;
import com.lowagie.text.pdf.OcspClient;
import com.lowagie.text.pdf.PdfDate;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfSignature;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import com.lowagie.text.pdf.PdfStamper;
import com.lowagie.text.pdf.PdfString;
import com.lowagie.text.pdf.PdfTemplate;
import com.lowagie.text.pdf.TSAClient;
import com.xpandit.datastructures.SignatureData;
import com.xpandit.datastructures.SignatureDetachedData;
import com.xpandit.digests.DigestAlgorithms;
import com.xpandit.enumerators.SignatureResponse;
import com.xpandit.utils.FileUtils;
import com.xpandit.utils.SignatureUtils;
import com.xpandit.utils.TSARequest;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Set;

/**
 * Description
 *
 * @author <a href="mailto:ricardo.vieira@xpand-it.com">RJSV</a>
 * @version $Revision : 1 $
 */

public class SignatureAssistant {

    /**
     * PDF Signature Variables - Related to the visual implementation of the signature
     */
    private static float fontSize = 8.5F;
    private static String TAG = SignatureAssistant.class.getSimpleName();
    private static Font layer2Font_Bold = new Font(Font.HELVETICA, fontSize, Font.BOLD);
    private static Font layer2Font_Discrete = new Font(Font.HELVETICA, fontSize, Font.NORMAL);
    private static SimpleDateFormat sdf_visibleSignature = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
    private static SignatureDetachedData sdd = new SignatureDetachedData();

    /**
     * @param fileName - The pdf file that contains the signature fields
     * @return
     * @throws IOException
     */
    public static ArrayList<String> getAllSignatureFieldNames(String fileName) {
        try {
            PdfReader reader = new PdfReader(fileName);
            AcroFields fields = reader.getAcroFields();
            Set<String> fldNames = fields.getFields().keySet();
            ArrayList<String> signatureFieldNames = new ArrayList<>();
            for (String fldName : fldNames) {
                signatureFieldNames.add(fldName);
            }
            reader.close();
            return signatureFieldNames;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * @param fileName - The file that contains the signature fields
     * @return
     * @throws IOException
     */
    public static ArrayList<String> getAllUnsignedSignatureFieldsNames(String fileName) throws IOException {
        try {
            PdfReader reader = new PdfReader(fileName);
            AcroFields fields = reader.getAcroFields();
            ArrayList<String> blankSignatureFields = new ArrayList<>();
            for (Object o : fields.getBlankSignatureNames()) {
                blankSignatureFields.add(String.valueOf(o));
            }
            reader.close();
            return blankSignatureFields;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * @param fileName - The file that contains the signature fields
     * @return
     * @throws IOException
     */
    public static ArrayList<String> getAllSignedSignatureFieldNames(String fileName) throws IOException {
        try {
            ArrayList<String> allSignatureFields = getAllSignatureFieldNames(fileName);
            ArrayList<String> blankSignatureFields = getAllUnsignedSignatureFieldsNames(fileName);
            if (blankSignatureFields == null)
                return allSignatureFields;
            else {
                for (String s : blankSignatureFields) {
                    if (allSignatureFields != null && allSignatureFields.contains(s)) {
                        allSignatureFields.remove(s);
                    }
                }
                return allSignatureFields;
            }
        } catch (Exception e) {
            return null;
        }
    }

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
        if (!fields.isEmpty()) {
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

        return null;
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
    public static SignatureResponse signPdf(String fileSource,
                                            String fileDestination,
                                            InputStream keyStore,
                                            char[] keyStorePassword,
                                            TSAClient tsaClient,
                                            SignatureData signatureData,
                                            Bitmap signatureImage) {
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
            PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0', null, true);

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

            byte[] hash = digest(data, messageDigest);
            Calendar cal = Calendar.getInstance();
            byte[] ocsp = null;
            PdfPKCS7 sgn = new PdfPKCS7(pk, chain, null, "SHA1", null, false);
            byte sh[] = sgn.getAuthenticatedAttributeBytes(hash, cal, ocsp);

            // breaking point
            sgn.update(sh, 0, sh.length);
            byte[] encodedSig;
            try {
                encodedSig = sgn.getEncodedPKCS7(hash, cal, tsaClient, ocsp);
            } catch (Exception e) {
                e.printStackTrace();
                return SignatureResponse.TSA_RESPONSE_ERROR;
            }
            if (encodedSig != null && (contentEstimated + 2 < encodedSig.length)) {
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

    public static SignatureDetachedData signPdfWithCC(String src,
                                                      String dest,
                                                      SignatureData sd,
                                                      String customCCNumber,
                                                      Certificate[] chain,
                                                      OcspClient ocspClient,
                                                      TSAClient tsaClient,
                                                      int estimatedSize,
                                                      Image img,
                                                      SignatureUtils.MyExternalSignature eid,
                                                      SignatureUtils.MyExternalDigest digest) throws GeneralSecurityException, IOException, DocumentException {

        X500Name x500name = new JcaX509CertificateHolder((X509Certificate) chain[0]).getSubject();
        RDN cn = x500name.getRDNs(BCStyle.CN)[0];
        String cnStr = IETFUtils.valueToString(cn.getFirst().getValue());
        RDN serialNumber = x500name.getRDNs(BCStyle.SERIALNUMBER)[0];

        String serialNumberStr = IETFUtils.valueToString(serialNumber.getFirst().getValue());
        img.setAbsolutePosition(0, 0);

        // Creating the reader and the stamper
        PdfReader reader = new PdfReader(src);

        int paragraphLeading = 10;
        Date date = new Date();
        dest = dest + ".pdf";

        FileOutputStream os = new FileOutputStream(dest);
        String tmp_path = dest.replace(".pdf", "_tmp.pdf");
        Log.i("debug", tmp_path);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');

        // Creating the appearance
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setAcro6Layers(true);
        appearance.setReason(sd.getReason());
        appearance.setLocation(sd.getLocation());
        appearance.setContact(sd.getAuthor());
        appearance.setVisibleSignature(sd.getSignatureName());

        // Creating the appearance for layer 2
        PdfTemplate n2 = appearance.getLayer(2);
        ColumnText ct = new ColumnText(n2);
        ct.setSimpleColumn(n2.getBoundingBox().getLeft(), n2.getBoundingBox().getBottom(), n2.getBoundingBox().getRight(), n2.getBoundingBox().getTop());
        ct.setExtraParagraphSpace(0);
        ct.setLeading(0);

        PdfPTable signatureBlockContainer = new PdfPTable(1);
        signatureBlockContainer.setSpacingAfter(0);
        signatureBlockContainer.setSpacingBefore(0);
        signatureBlockContainer.setWidthPercentage(100);

        // FIRST BLOCK
        // Creating the Cell to accommodate the signature holder name
        PdfPCell firstBlock = new PdfPCell();
        firstBlock.setBorder(Rectangle.NO_BORDER);
        firstBlock.setFixedHeight(28);

        // LABEL
        Paragraph firstBlockLabel = new Paragraph();
        Chunk firstBlockLabelText = new Chunk("Este documento foi assinado por:");
        firstBlockLabelText.setFont(layer2Font_Discrete);
        firstBlockLabel.setLeading(paragraphLeading - 5);
        firstBlockLabel.setSpacingAfter(2);
        firstBlockLabel.add(firstBlockLabelText);
        firstBlock.addElement(firstBlockLabel);

        // NAME
        Paragraph firstBlockName = new Paragraph();
        Chunk firstBlockNameText;
        if (cnStr.length() > 30) {
            //truncate Name just to keep max two lines for the name
            if (cnStr.length() > 65) {
                firstBlockNameText = new Chunk(cnStr.substring(0, 65).toUpperCase());
            } else {
                firstBlockNameText = new Chunk(cnStr.toUpperCase());
            }
        } else {
            firstBlockNameText = new Chunk(cnStr.toUpperCase());
        }
        firstBlockNameText.setFont(layer2Font_Bold);
        firstBlockName.add(firstBlockNameText);
        firstBlockName.setLeading(paragraphLeading - 2);
        firstBlockName.setSpacingAfter(0);
        firstBlockName.setSpacingBefore(0);
        firstBlock.addElement(firstBlockName);
        signatureBlockContainer.addCell(firstBlock);

        // SECOND BLOCK
        // Creating the Cell to accommodate the signature's holder card number and date
        PdfPCell secondBlock = new PdfPCell();
        secondBlock.setBorder(Rectangle.NO_BORDER);

        // CC NUMBER
        String ccNumber = "" + serialNumberStr.substring(2);
        if (customCCNumber != null && !customCCNumber.isEmpty()) {
            ccNumber = customCCNumber;
        }
        Paragraph secondBlockLabelAndCitizenCard = new Paragraph();
        Chunk citizenCardLabel = new Chunk("Cartão Cidadão Nº: ");
        citizenCardLabel.setFont(layer2Font_Discrete);
        secondBlockLabelAndCitizenCard.add(citizenCardLabel);
        Chunk citizenCardNumber = new Chunk(ccNumber);
        citizenCardNumber.setFont(layer2Font_Bold);
        secondBlockLabelAndCitizenCard.add(citizenCardNumber);
        secondBlockLabelAndCitizenCard.setLeading(paragraphLeading - 2);
        secondBlockLabelAndCitizenCard.setSpacingAfter(2);
        secondBlock.addElement(secondBlockLabelAndCitizenCard);

        // DATE
        Paragraph secondBlockDate = new Paragraph();
        Chunk dateLabel = new Chunk("Data: ");
        dateLabel.setFont(layer2Font_Discrete);
        secondBlockDate.add(dateLabel);
        Chunk dateValue = new Chunk("" + sdf_visibleSignature.format(date));
        dateValue.setFont(layer2Font_Bold);
        secondBlockDate.add(dateValue);
        secondBlockDate.setLeading(paragraphLeading - 2);
        secondBlock.addElement(secondBlockDate);
        signatureBlockContainer.addCell(secondBlock);
        ct.addElement(signatureBlockContainer);
        Log.d(TAG, "Signing > Signature Height: " + n2.getHeight());
        ct.go();

        // THIRD BLOCK (IMAGE)
        int height = 60;
        int width = 92;
        n2.addImage(img, width, 0, 0, (height / 3), n2.getWidth() - width, 0.5F, true);

        return signDetached(appearance, digest, eid, chain, ocspClient, tsaClient, estimatedSize, reader, os, stamper);

    }


    public static SignatureDetachedData signDetached(PdfSignatureAppearance sap,
                                                     SignatureUtils.MyExternalDigest myExternalDigest,
                                                     SignatureUtils.MyExternalSignature externalSignature,
                                                     Certificate[] chain,
                                                     OcspClient ocspClient,
                                                     TSAClient tsaClient,
                                                     int estimatedSize,
                                                     PdfReader reader,
                                                     FileOutputStream os,
                                                     PdfStamper stamper) throws IOException, DocumentException, GeneralSecurityException {
        if (estimatedSize == 0) {
            estimatedSize = 8192;
            if (ocspClient != null) {
                estimatedSize += 4192;
            }
            if (tsaClient != null) {
                estimatedSize += 4192;
            }
        }
        PdfSignature var24 = new PdfSignature(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
        var24.setReason(sap.getReason());
        var24.setLocation(sap.getLocation());
        var24.setContact(sap.getContact());
        var24.setDate(new PdfDate(sap.getSignDate()));
        sap.setCryptoDictionary(var24);
        HashMap var25 = new HashMap();
        var25.put(PdfName.CONTENTS, estimatedSize * 2 + 2);
        sap.preClose(var25);
        String hashAlgorithm = externalSignature.getHashAlgorithm();
        PdfPKCS7 sgn = new PdfPKCS7(null, chain, null, hashAlgorithm, null, false);
        InputStream data = sap.getRangeStream();
        byte[] hash = DigestAlgorithms.digest(data, myExternalDigest.getMessageDigest(hashAlgorithm));

        Date date = new Date();
        Calendar car = Calendar.getInstance();
        car.setTime(date);

        byte[] ocsp = null;
        if (chain.length >= 2 && ocspClient != null) {
            ocsp = ocspClient.getEncoded();
        }
        sdd.setHash(hash);
        sdd.setCar(car);
        sdd.setTsaClient(tsaClient);
        sdd.setOcsp(ocsp);
        sdd.setEstimatedSize(estimatedSize);
        sdd.setSgn(sgn);
        sdd.setSap(sap);
        sdd.setCar(car);
        sdd.setExternalSignature(externalSignature);
        sdd.setReader(reader);
        sdd.setOs(os);
        sdd.setStamper(stamper);
        byte[] sh = sgn.getAuthenticatedAttributeBytes(hash, car, ocsp);
        sdd.setAuthenticatedAttributeBytes(sh);
        return sdd;
    }


    public static void signDetachedFinish(byte[] data, SignatureAssistantInterface sai) {
        new signDetachedFinish(data, sai).execute();
    }

    public static class signDetachedFinish extends AsyncTask<byte[], String, String> {

        private byte[] data;
        private SignatureAssistantInterface sai;

        public signDetachedFinish(byte[] data, SignatureAssistantInterface sai) {
            this.data = data;
            this.sai = sai;
        }

        protected void onPreExecute() {
            Log.d(TAG, "Signing > Beginning the sign detach finish async task");
        }

        @Override
        protected String doInBackground(byte[]... params) {
            sdd.getSgn().setExternalDigest(data, null, sdd.getExternalSignature().getEncryptionAlgorithm());
            byte[] encodedSig = sdd.getSgn().getEncodedPKCS7(sdd.getHash(), sdd.getCar(), sdd.getTsaClient(), sdd.getOcsp());
            if (sdd.getEstimatedSize() < encodedSig.length) {
                try {
                    throw new IOException("Not enough space");
                } catch (IOException e) {
                    Log.d(TAG, e.toString());
                }
            } else {
                byte[] paddedSig = new byte[sdd.getEstimatedSize()];
                System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length);
                PdfDictionary dic2 = new PdfDictionary();
                dic2.put(PdfName.CONTENTS, (new PdfString(paddedSig)).setHexWriting(true));

                try {
                    if (sdd.getSap().isPreClosed()) {
                        sdd.getSap().close(dic2);
                    } else {
                        sdd.getStamper().close();
                    }
                } catch (IOException | DocumentException e) {
                    Log.d(TAG, e.toString());
                }
            }
            try {
                sdd.getOs().close();
                sdd.getReader().close();
            } catch (IOException e) {
                Log.d(TAG, e.toString());
            }
            return "success";
        }

        protected void onPostExecute(String result) {
            if (result.equals("error")) {
                sai.finishDigitalSignatureProcess("error");
            } else {
                Log.d(TAG, "Signing > Finished the sign detach async task");
                sai.finishDigitalSignatureProcess("success");
            }
        }

    }

    public static void timestampPdf(String sourceFile, String destinationFile, TSARequest tsaRequest, String signatureName) throws IOException, DocumentException, GeneralSecurityException {
        PdfReader r = new PdfReader(sourceFile);
        FileOutputStream fos = new FileOutputStream(destinationFile);
        PdfStamper stp = PdfStamper.createSignature(r, fos, '\0', null, true);
        PdfSignatureAppearance sigAppearance = stp.getSignatureAppearance();
        int contentEstimated = tsaRequest.getTokenSizeEstimate();
        sigAppearance.setVisibleSignature(new Rectangle(0.0F, 0.0F, 0.0F, 0.0F), 1, signatureName);
        PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, new PdfName("ETSI.RFC3161"));
        dic.put(PdfName.TYPE, new PdfName("DocTimeStamp"));
        sigAppearance.setCryptoDictionary(dic);
        HashMap exc = new HashMap();
        exc.put(PdfName.CONTENTS, new Integer(contentEstimated * 2 + 2));
        sigAppearance.preClose(exc);
        InputStream stream = sigAppearance.getRangeStream();
        MessageDigest messageDigest = tsaRequest.getMessageDigest();
        byte[] buf = new byte[4096];

        int n;
        while ((n = stream.read(buf)) > 0) {
            messageDigest.update(buf, 0, n);
        }

        byte[] tsImprint = messageDigest.digest();

        byte[] tsToken;
        try {
            tsToken = tsaRequest.getTimeStampToken(tsImprint);
        } catch (Exception var14) {
            throw new GeneralSecurityException(var14);
        }
        if (contentEstimated + 2 < tsToken.length) {
            throw new IOException("Not enough space");
        } else {
            byte[] paddedSig = new byte[contentEstimated];
            System.arraycopy(tsToken, 0, paddedSig, 0, tsToken.length);
            PdfDictionary dic2 = new PdfDictionary();
            dic2.put(PdfName.CONTENTS, (new PdfString(paddedSig)).setHexWriting(true));
            sigAppearance.close(dic2);
        }

    }

    public static byte[] digest(InputStream data, MessageDigest messageDigest) throws GeneralSecurityException, IOException {
        byte[] buf = new byte[8192];
        int n;
        while ((n = data.read(buf)) > 0) {
            messageDigest.update(buf, 0, n);
        }
        return messageDigest.digest();
    }

}
