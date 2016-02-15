package datastructures;

import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import com.lowagie.text.pdf.PdfStamper;
import com.lowagie.text.pdf.TSAClient;

import java.io.FileOutputStream;
import java.util.Calendar;

import signature.SignatureUtils;

/**
 * Description
 *
 * @author <a href="mailto:ricardo.vieira@xpand-it.com">RJSV</a>
 * @version $Revision : 1 $
 */

public class SignatureDetachedData {

    // region Class variables
    private PdfPKCS7 sgn;
    private byte[] hash;
    private Calendar car;
    private TSAClient tsaClient;
    private byte[] ocsp;
    private int estimatedSize;
    private PdfSignatureAppearance sap;
    private SignatureUtils.MyExternalSignature externalSignature;
    private PdfReader reader;
    private FileOutputStream os;
    private PdfStamper stamper;
    private byte[] authenticatedAttributeBytes;
    // endregion

    // region Constructors
    public SignatureDetachedData() {

    }
    // endregion

    // region Setters and Getters
    public PdfPKCS7 getSgn() {
        return sgn;
    }

    public void setSgn(PdfPKCS7 sgn) {
        this.sgn = sgn;
    }

    public byte[] getHash() {
        return hash;
    }

    public void setHash(byte[] hash) {
        this.hash = hash;
    }

    public Calendar getCar() {
        return car;
    }

    public void setCar(Calendar car) {
        this.car = car;
    }

    public TSAClient getTsaClient() {
        return tsaClient;
    }

    public void setTsaClient(TSAClient tsaClient) {
        this.tsaClient = tsaClient;
    }

    public byte[] getOcsp() {
        return ocsp;
    }

    public void setOcsp(byte[] ocsp) {
        this.ocsp = ocsp;
    }

    public int getEstimatedSize() {
        return estimatedSize;
    }

    public void setEstimatedSize(int estimatedSize) {
        this.estimatedSize = estimatedSize;
    }

    public PdfSignatureAppearance getSap() {
        return sap;
    }

    public void setSap(PdfSignatureAppearance sap) {
        this.sap = sap;
    }

    public SignatureUtils.MyExternalSignature getExternalSignature() {
        return externalSignature;
    }

    public void setExternalSignature(SignatureUtils.MyExternalSignature externalSignature) {
        this.externalSignature = externalSignature;
    }

    public PdfReader getReader() {
        return reader;
    }

    public void setReader(PdfReader reader) {
        this.reader = reader;
    }

    public FileOutputStream getOs() {
        return os;
    }

    public void setOs(FileOutputStream os) {
        this.os = os;
    }

    public PdfStamper getStamper() {
        return stamper;
    }

    public void setStamper(PdfStamper stamper) {
        this.stamper = stamper;
    }

    public byte[] getAuthenticatedAttributeBytes() {
        return authenticatedAttributeBytes;
    }

    public void setAuthenticatedAttributeBytes(byte[] authenticatedAttributeBytes) {
        this.authenticatedAttributeBytes = authenticatedAttributeBytes;
    }
// endregion

}
