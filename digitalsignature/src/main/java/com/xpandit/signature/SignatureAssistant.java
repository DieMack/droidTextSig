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
import com.lowagie.text.pdf.OcspClientBouncyCastle;
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
import java.util.List;
import java.util.Locale;
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
    private static SimpleDateFormat sdf_visibleSignature = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss", Locale.GERMAN);
    private static SignatureDetachedData sdd = new SignatureDetachedData();

    /**
     * @param fileName - The pdf file that contains the signature fields
     * @returns the list of all the signature fields
     */
    public static ArrayList<String> getAllSignatureFieldNames(String fileName) {
        try {
            PdfReader reader = new PdfReader(fileName);
            AcroFields fields = reader.getAcroFields();
            Set<String> fieldNames = fields.getFields().keySet();
            ArrayList<String> signatureFieldNames = new ArrayList<>();
            for (String fldName : fieldNames) {
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
     * @returns the list of all the unsigned signature fields
     */
    public static ArrayList<String> getAllUnsignedSignatureFieldsNames(String fileName) {
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
     * @returns the list of all the signed field names
     */
    public static ArrayList<String> getAllSignedSignatureFieldNames(String fileName) {
        try {
            ArrayList<String> allSignatureFields = getAllSignatureFieldNames(fileName);
            ArrayList<String> blankSignatureFields = getAllUnsignedSignatureFieldsNames(fileName);
            if (blankSignatureFields == null) {
                return allSignatureFields;
            } else {
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
     * @param fileName          - The source pdf file
     * @param signatureNameList - The list of the signatures that need the Signature Data
     * @return SignatureData
     * @throws IOException
     */
    public static ArrayList<SignatureData> getFormFieldPositions(String fileName, List<String> signatureNameList) throws IOException {
        ArrayList<SignatureData> signatureDataList = new ArrayList<>();
        PdfReader reader = new PdfReader(fileName);
        AcroFields form = reader.getAcroFields();
        Set fields = form.getFields().keySet();
        if (!fields.isEmpty()) {
            for (String signatureName : signatureNameList) {
                switch (form.getFieldType(signatureName)) {
                    case AcroFields.FIELD_TYPE_SIGNATURE:
                        if (form.getFieldPositions(signatureName).length > 0) {
                            float[] sigData = form.getFieldPositions(signatureName);
                            int page = (int) sigData[0];
                            float llx = sigData[1];
                            float lly = sigData[2];
                            float urx = sigData[3];
                            float ury = sigData[4];
                            Rectangle rect = reader.getPageSize(page);
                            float pageWidth = rect.getWidth();
                            float pageHeight = rect.getHeight();
                            SignatureData sd = new SignatureData();
                            sd.setSignatureName(signatureName);
                            sd.setPage(page);
                            sd.setPageWidth((int) pageWidth);
                            sd.setPageHeight((int) pageHeight);
                            sd.setLeft(llx);
                            sd.setDown(lly);
                            sd.setRight(urx);
                            sd.setUp(ury);
                            signatureDataList.add(sd);
                        }
                        break;
                    default:
                        break;
                }
            }
            reader.close();
        }
        return signatureDataList;
    }

    /**
     * @param fileSource       - The input file used that is going to be signed
     * @param fileDestination  - The output file of the signing operation
     * @param keyStore         - The keystore containing the Private Key file
     * @param keyStorePassword - The Private key
     * @param tsaClient        - The Timestamp Client that is used to timestamp the operation. If null, the hour of the clock will be used
     * @param signatureData    - The Signature Data object that contains all relevant information regarding the signature
     * @return
     */
    public static SignatureResponse signPdf(String fileSource,
                                            String fileDestination,
                                            InputStream keyStore,
                                            char[] keyStorePassword,
                                            TSAClient tsaClient,
                                            OcspClientBouncyCastle OcspClient,
                                            SignatureData signatureData) {
        try {
            // Before starting the procedure, confirm that the fileSource exists
            // Check if the source file equals the destination file.
            // If they are the same, copy the source to the source_tmp file
            if (!FileUtils.fileExists(fileSource)) {
                return SignatureResponse.FILE_NOT_EXIST;
            }
            boolean sameInOut = fileSource.equals(fileDestination);
            String myDest = sameInOut ? fileSource + "_tmp" : fileSource;
            if (sameInOut) {
                FileUtils.copyFile(fileSource, myDest);
            }
            try {
                // Combine the KeyStore and the KeyStorePassword into the Certificate chain
                Security.addProvider(new BouncyCastleProvider());
                KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
                try {
                    ks.load(keyStore, keyStorePassword);
                } catch (Exception e) {
                    return SignatureResponse.CERTIFICATE_KEY_ERROR;
                }
                String alias = ks.aliases().nextElement();
                PrivateKey pk = (PrivateKey) ks.getKey(alias, keyStorePassword);
                Certificate[] chain = ks.getCertificateChain(alias);

                // Creating the PDF Signature that will contain the relevant signature information
                PdfSignature dictionary = new PdfSignature(PdfName.ADOBE_PPKLITE, new PdfName("adbe.pkcs7.detached"));
                dictionary.setContact(signatureData.getAuthor());
                dictionary.setLocation(signatureData.getLocation());
                dictionary.setReason(signatureData.getReason());
                dictionary.setDate(new PdfDate());
                PdfReader reader;
                //Add signature byte contents as additional info
                if (signatureData.getContent() != null) {
                    reader = new PdfReader(myDest);
                    PdfStamper stamper = new PdfStamper(reader,
                            new FileOutputStream(myDest + "t"), '\0', true);
                    //noinspection unchecked
                    HashMap info = reader.getInfo();
                    info.put(signatureData.getSignatureName(), new String(signatureData.getContent(), "UTF-8"));
                    stamper.setMoreInfo(info);
                    stamper.close();
                    reader.close();
                    FileUtils.deleteFile(myDest);
                    FileUtils.renameFile(myDest + "t", myDest);
                }

                // Instantiate the PDFReader to operate with the file
                // Create the Appearance from the PDFReader (through the Stamper)
                reader = new PdfReader(myDest);
                FileOutputStream os = new FileOutputStream(String.format(fileDestination, 1));
                PdfSignatureAppearance appearance = PdfStamper.createSignature(reader, os, '\0', null, true).getSignatureAppearance();

                // Load the image inside the SignatureData into the Appearance (equal to the user hand-drawn signature)
                // Setting the layers' text to empty so we don't have unnecessary text covering the signature
                // Passing the keystore chain and the private key into the appearance
                // Passing the signature information into the appearance
                if (signatureData.getSignatureImage() != null) {
                    ByteArrayOutputStream stream = new ByteArrayOutputStream();
                    signatureData.getSignatureImage().compress(Bitmap.CompressFormat.PNG, 100, stream);
                    Image image = Image.getInstance(stream.toByteArray());
                    appearance.setImage(image);
                }
                appearance.setLayer2Text("");
                appearance.setLayer4Text("");
                appearance.setAcro6Layers(true);
                appearance.setVisibleSignature(signatureData.getSignatureName());
                appearance.setCrypto(pk, chain, null, PdfSignatureAppearance.WINCER_SIGNED);
                appearance.setCryptoDictionary(dictionary);

                // Reserve space for the signature content
                // - Before closing the appearance, we need to estimate the length of the signature
                int contentEstimated = 15000;
                HashMap<PdfName, Integer> exc = new HashMap<>();
                exc.put(PdfName.CONTENTS, contentEstimated * 2 + 2);
                appearance.preClose(exc);

                // - Create a message digest to 'digest' the appearance input stream
                // - Obtaining the appearance range stream as an input stream
                // - Digest the signature appearance into the byte[]
                MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
                InputStream data = appearance.getRangeStream();
                byte[] hash = digest(8192, data, messageDigest);
                byte[] ocsp = OcspClient != null ? OcspClient.getEncoded() : null;
                Calendar cal = Calendar.getInstance();

                // Create the signed hash for the signature and update it with the Authenticated Attributes
                PdfPKCS7 sgn = new PdfPKCS7(pk, chain, null, "SHA1", null, false);
                byte[] sh = sgn.getAuthenticatedAttributeBytes(hash, cal, ocsp);
                sgn.update(sh, 0, sh.length);
                byte[] encodedSig;
                try {
                    encodedSig = sgn.getEncodedPKCS7(hash, cal, tsaClient, ocsp);
                } catch (Exception e) {
                    return SignatureResponse.FAILURE;
                }
                if (encodedSig != null && (contentEstimated + 2 < encodedSig.length)) {
                    return SignatureResponse.NOT_ENOUGH_SPACE;
                }
                byte[] paddedSig = new byte[contentEstimated];
                if (encodedSig != null) {
                    System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length);
                }
                // Add signature content and close the appearance
                PdfDictionary dictionary2 = new PdfDictionary();
                dictionary2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
                appearance.close(dictionary2);
            } catch (Exception e) {
                e.printStackTrace();
                if (sameInOut) {
                    FileUtils.deleteFile(fileSource);
                    FileUtils.renameFile(myDest, fileSource);
                }
                return SignatureResponse.FAILURE;
            }
            // After signing the source file, delete the
            if (sameInOut) {
                FileUtils.deleteFile(myDest);
            }
            return SignatureResponse.SUCCESS;
        } catch (IOException e) {
            e.printStackTrace();
            return SignatureResponse.FAILURE;
        }
    }

    /**
     * @param fileSource      - The input file used that is going to be signed
     * @param fileDestination - The output file of the signing operation
     * @param signatureData   - The Signature Data object that contains all relevant information regarding the signature
     * @param customCCNumber  - The custom Citizen Card Number to be inserted on the signature
     * @param certChain       - The Certificate chain
     * @param ocspClient      - The Online Certificate Status Protocol Client
     * @param tsaClient       - The Timestamp Client
     * @param estimatedSize   - The estimated size of the token
     * @param img             - The citizen Card logo image that is passed (anything else works as well!)
     * @param eid             - The External Signature
     * @param digest          - The External Digest
     * @return
     * @throws GeneralSecurityException
     * @throws IOException
     * @throws DocumentException
     */
    public static SignatureDetachedData signPdfWithCC(String fileSource,
                                                      String fileDestination,
                                                      SignatureData signatureData,
                                                      String customCCNumber,
                                                      Certificate[] certChain,
                                                      OcspClient ocspClient,
                                                      TSAClient tsaClient,
                                                      int estimatedSize,
                                                      Image img,
                                                      SignatureUtils.MyExternalSignature eid,
                                                      SignatureUtils.MyExternalDigest digest) throws GeneralSecurityException, IOException, DocumentException {
        try {
            // Before starting the procedure, confirm that the fileSource exists
            // Check if the source file equals the destination file.
            // If they are the same, copy the source to the source_tmp file
            if (!FileUtils.fileExists(fileSource)) {
                return null;
            }
            boolean sameInOut = fileSource.equals(fileDestination);
            String myDest = sameInOut ? fileSource + "_tmp" : fileSource;
            if (sameInOut) {
                FileUtils.copyFile(fileSource, myDest);
            }
            try {
                X500Name x500name = new JcaX509CertificateHolder((X509Certificate) certChain[0]).getSubject();
                RDN cn = x500name.getRDNs(BCStyle.CN)[0];
                String cnStr = IETFUtils.valueToString(cn.getFirst().getValue());
                RDN serialNumber = x500name.getRDNs(BCStyle.SERIALNUMBER)[0];
                String serialNumberStr = IETFUtils.valueToString(serialNumber.getFirst().getValue());
                img.setAbsolutePosition(0, 0);

                // Creating the reader and the stamper
                PdfReader reader = new PdfReader(myDest);

                int paragraphLeading = 10;
                Date date = new Date();

                FileOutputStream os = new FileOutputStream(fileDestination);
                String tmp_path = fileDestination.replace(".pdf", "_tmp.pdf");
                Log.d("debug", tmp_path);
                PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0', null, true);

                // Creating the appearance
                PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
                appearance.setAcro6Layers(true);
                appearance.setReason(signatureData.getReason());
                appearance.setLocation(signatureData.getLocation());
                appearance.setContact(signatureData.getAuthor());
                appearance.setVisibleSignature(signatureData.getSignatureName());

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

                // ------------------------------------------------------------------------------- //
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

                // ------------------------------------------------------------------------------- //
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
                return signDetached(appearance, digest, eid, certChain, ocspClient, tsaClient, estimatedSize, reader, os, stamper);
            } catch (Exception e) {
                e.printStackTrace();
                if (sameInOut) {
                    FileUtils.deleteFile(fileSource);
                    FileUtils.renameFile(myDest, fileSource);
                }
                throw e;
            }
        } catch (IOException e) {
            e.printStackTrace();
            throw e;
        }
    }

    /**
     * The second part of the CitizenCard Signature Procedure. Due to asynchronous requirements, this method was broken
     * into two 'SignDetached and 'SignDetachedFinish'
     *
     * @throws IOException
     * @throws DocumentException
     * @throws GeneralSecurityException
     */
    public static SignatureDetachedData signDetached(PdfSignatureAppearance sap,
                                                     SignatureUtils.MyExternalDigest myExternalDigest,
                                                     SignatureUtils.MyExternalSignature externalSignature,
                                                     Certificate[] chain,
                                                     OcspClient ocspClient,
                                                     TSAClient tsaClient,
                                                     int estimatedSize,
                                                     PdfReader reader,
                                                     FileOutputStream os,
                                                     PdfStamper stamper) {
        try {
            // Calculating the estimated size
            if (estimatedSize == 0) {
                estimatedSize = 8192;
                estimatedSize = ocspClient != null ? estimatedSize + 4192 : estimatedSize;
                estimatedSize = tsaClient != null ? estimatedSize + 4192 : estimatedSize;
            }
            // Creating the PDF Signature that will contain the relevant signature information
            PdfSignature dictionary = new PdfSignature(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
            dictionary.setReason(sap.getReason());
            dictionary.setLocation(sap.getLocation());
            dictionary.setContact(sap.getContact());
            dictionary.setDate(new PdfDate(sap.getSignDate()));
            sap.setCryptoDictionary(dictionary);

            // Reserve space for the signature content
            // Before closing the appearance, we need to estimate the length of the signature
            HashMap<PdfName, Integer> var25 = new HashMap<>();
            var25.put(PdfName.CONTENTS, estimatedSize * 2 + 2);
            sap.preClose(var25);

            // Create the signed hash for the signature and update it with the Authenticated Attributes
            String hashAlgorithm = externalSignature.getHashAlgorithm();
            PdfPKCS7 sgn = new PdfPKCS7(null, chain, null, hashAlgorithm, null, false);
            InputStream data = sap.getRangeStream();
            byte[] hash = DigestAlgorithms.digest(data, myExternalDigest.getMessageDigest(hashAlgorithm));

            // Creating the calendar
            Calendar calendar = Calendar.getInstance();
            calendar.setTime(new Date());

            byte[] ocsp = null;
            if (chain.length >= 2 && ocspClient != null) {
                ocsp = ocspClient.getEncoded();
            }
            sdd.setHash(hash);
            sdd.setCalendar(calendar);
            sdd.setTsaClient(tsaClient);
            sdd.setOcsp(ocsp);
            sdd.setEstimatedSize(estimatedSize);
            sdd.setSgn(sgn);
            sdd.setSap(sap);
            sdd.setExternalSignature(externalSignature);
            sdd.setReader(reader);
            sdd.setOs(os);
            sdd.setStamper(stamper);
            byte[] sh = sgn.getAuthenticatedAttributeBytes(hash, calendar, ocsp);
            sdd.setAuthenticatedAttributeBytes(sh);
            return sdd;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Continuation of the previous method (asynchronous requirements)
     *
     * @param data - The Byte array that will be passed to the external digest method
     * @param sai  - The Signature Assistant Interface that is going to be called whenever this method is finished
     */
    public static void signDetachedFinish(byte[] data, SignatureAssistantInterface sai) {
        new signDetachedFinish(data, sai).execute();
    }

    /**
     * @param fileSource      - The input file used that is going to be timestamped
     * @param fileDestination - The output file of the timestamping operation
     * @param tsaRequest      - The request that contains the Timestamping credentials and variables
     * @param signatureName   - The signature name (optional). If null, will attach the LTV timestamp to the document
     */
    public static SignatureResponse timestampPdf(String fileSource, String fileDestination, TSARequest tsaRequest, String signatureName) {
        try {
            // Before starting the procedure, confirm that the fileSource exists
            // Check if the source file equals the destination file.
            // If they are the same, copy the source to the source_tmp file
            if (!FileUtils.fileExists(fileSource)) {
                return SignatureResponse.FILE_NOT_EXIST;
            }
            String backupFile = fileSource + "_backup";
            FileUtils.copyFile(fileSource, backupFile);
            try {
                // Creating the PDF Signature that will contain the relevant signature information
                PdfSignature dictionary = new PdfSignature(PdfName.ADOBE_PPKLITE, new PdfName("ETSI.RFC3161"));
                dictionary.put(PdfName.TYPE, new PdfName("DocTimeStamp"));

                // Instantiate the PDFReader to operate with the file
                // Create the Appearance from the PDFReader (through the Stamper)
                // Passing the signature information into the appearance
                PdfReader reader = new PdfReader(fileSource);
                FileOutputStream os = new FileOutputStream(fileDestination);
                PdfSignatureAppearance appearance = PdfStamper.createSignature(reader, os, '\0', null, true).getSignatureAppearance();
                appearance.setVisibleSignature(new Rectangle(0.0F, 0.0F, 0.0F, 0.0F), 1, signatureName);
                appearance.setCryptoDictionary(dictionary);

                // Reserve space for the signature content
                // Before closing the appearance, we need to estimate the length of the signature
                int contentEstimated = tsaRequest.getTokenSizeEstimate();
                HashMap<PdfName, Integer> exc = new HashMap<>();
                exc.put(PdfName.CONTENTS, contentEstimated * 2 + 2);
                appearance.preClose(exc);

                // Create a message digest to 'digest' the appearance input stream
                // Obtaining the appearance range stream as an input stream
                // Digest the signature appearance into the byte[]
                InputStream stream = appearance.getRangeStream();
                MessageDigest messageDigest = tsaRequest.getMessageDigest();
                byte[] tsImprint = digest(4096, stream, messageDigest);
                byte[] tsToken;
                try {
                     tsToken = tsaRequest.getTimeStampToken(tsImprint);
                } catch (Exception var14) {
                    throw new GeneralSecurityException(var14);
                }
                if (contentEstimated + 2 < tsToken.length) {
                    return SignatureResponse.NOT_ENOUGH_SPACE;
                } else {
                    byte[] paddedSig = new byte[contentEstimated];
                    System.arraycopy(tsToken, 0, paddedSig, 0, tsToken.length);
                    // Add signature content and close the appearance
                    PdfDictionary dictionary2 = new PdfDictionary();
                    dictionary2.put(PdfName.CONTENTS, (new PdfString(paddedSig)).setHexWriting(true));
                    appearance.close(dictionary2);
                }
            } catch (Exception e) {
                e.printStackTrace();
                FileUtils.deleteFile(fileDestination);
                FileUtils.deleteFile(fileSource);
                FileUtils.renameFile(backupFile, fileSource);
                return SignatureResponse.TSA_RESPONSE_ERROR;
            }
            FileUtils.deleteFile(backupFile);
            return SignatureResponse.SUCCESS;
        } catch (IOException e) {
            e.printStackTrace();
            return SignatureResponse.TSA_RESPONSE_ERROR;
        }
    }

    public static byte[] digest(int byteArraySize, InputStream data, MessageDigest messageDigest) throws GeneralSecurityException, IOException {
        byte[] buf = new byte[byteArraySize];
        int n;
        while ((n = data.read(buf)) > 0) {
            messageDigest.update(buf, 0, n);
        }
        return messageDigest.digest();
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
            try {
                sdd.getSgn().setExternalDigest(data, null, sdd.getExternalSignature().getEncryptionAlgorithm());
                byte[] encodedSig = sdd.getSgn().getEncodedPKCS7(sdd.getHash(), sdd.getCalendar(), sdd.getTsaClient(), sdd.getOcsp());
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
            } catch (Exception e) {
                return "error";
            }
            return "success";
        }

        protected void onPostExecute(String result) {
            if (result.equals("success")) {
                sai.finishDigitalSignatureProcess("success");
            } else {
                sai.finishDigitalSignatureProcess("error");
            }
            Log.d(TAG, "Signing > Finished the sign detach async task");
        }

    }
}
