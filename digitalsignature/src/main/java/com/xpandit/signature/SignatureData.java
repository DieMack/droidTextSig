package com.xpandit.signature;

import java.io.Serializable;


/**
 * Description
 *
 * @author <a href="mailto:ricardo.vieira@xpand-it.com">RJSV</a>
 * @version $Revision : 1 $
 */

public class SignatureData implements Serializable {

    // region Class Variables
    private String signatureName;
    private Integer signaturePage;
    private Integer page;
    private Integer pageWidth;
    private Integer pageHeight;
    private Float left;
    private Float down;
    private Float right;
    private Float up;
    private String author;
    private String reason;
    private String location;
    // endregion

    // region Constructors
    public SignatureData() {
    }
    // endregion

    // region Getters and Setters
    public String getSignatureName() {
        return signatureName;
    }

    public void setSignatureName(String signatureName) {
        this.signatureName = signatureName;
    }

    public Integer getSignaturePage() {
        return signaturePage;
    }

    public void setSignaturePage(Integer signaturePage) {
        this.signaturePage = signaturePage;
    }

    public Integer getPage() {
        return page;
    }

    public void setPage(Integer page) {
        this.page = page;
    }

    public Integer getPageWidth() {
        return pageWidth;
    }

    public void setPageWidth(Integer pageWidth) {
        this.pageWidth = pageWidth;
    }

    public Integer getPageHeight() {
        return pageHeight;
    }

    public void setPageHeight(Integer pageHeight) {
        this.pageHeight = pageHeight;
    }

    public Float getLeft() {
        return left;
    }

    public void setLeft(Float left) {
        this.left = left;
    }

    public Float getDown() {
        return (float) Math.floor(down);
    }

    public void setDown(Float down) {
        this.down = down;
    }

    public Float getRight() {
        return right;
    }

    public void setRight(Float right) {
        this.right = right;
    }

    public Float getUp() {
        return (float) Math.ceil(up);
    }

    public void setUp(Float up) {
        this.up = up;
    }

    public String getAuthor() {
        return author;
    }

    public void setAuthor(String author) {
        this.author = author;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }
    // endregion

    // region General Methods

    @Override
    public String toString() {
        return "SignatureData{" +
                "signatureName='" + signatureName + '\'' +
                ", signaturePage=" + signaturePage +
                ", page=" + page +
                ", pageWidth=" + pageWidth +
                ", pageHeight=" + pageHeight +
                ", left=" + left +
                ", down=" + down +
                ", right=" + right +
                ", up=" + up +
                '}';
    }
    // endregion
}

