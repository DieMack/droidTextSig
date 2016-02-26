package com.xpandit.enumerators;

/**
 * Description
 *
 * @author <a href="mailto:ricardo.vieira@xpand-it.com">RJSV</a>
 * @version $Revision : 1 $
 */

public enum SignatureResponse {

    FAILURE(-1),
    SUCCESS(0),
    FILE_NOT_EXIST(1),
    TSA_RESPONSE_ERROR(2),
    NOT_ENOUGH_SPACE(3),
    CONNECTION_ERROR(4),
    CERTIFICATE_KEY_ERROR(5);

    private int position;

    SignatureResponse(int n) {
        position = n;
    }

    public static SignatureResponse match(int n) {
        switch (n) {
            case -1:
                return FAILURE;
            case 0:
                return SUCCESS;
            case 1:
                return FILE_NOT_EXIST;
            case 2:
                return TSA_RESPONSE_ERROR;
            case 3:
                return NOT_ENOUGH_SPACE;
            case 4:
                return CONNECTION_ERROR;
            case 5:
                return CERTIFICATE_KEY_ERROR;
            default:
                break;
        }
        return null;
    }

    public String getSigningMessage() {
        switch (position) {
            case -1:
                return "Failure executing the signature";
            case 0:
                return "Signature successfully executed";
            case 1:
                return "Failure executing the signature. File does not exist";
            case 2:
                return "Failure executing the signature. TSA error";
            case 3:
                return "Failure executing the signature. Not enough space";
            case 4:
                return "Failure executing the signature. Connection error";
            case 5:
                return "Failure executing the signature. Incorrect password/certificate combination";
            default:
                break;
        }
        return null;
    }

    public String getTimestampingMessage() {
        switch (position) {
            case -1:
                return "Failure executing the timestamp";
            case 0:
                return "Timestamp successfully executed";
            case 1:
                return "Failure executing the timestamp. File does not exist";
            case 2:
                return "Failure executing the timestamp. TSA error";
            case 3:
                return "Failure executing the timestamp. Not enough space";
            case 4:
                return "Failure executing the timestamp. Connection error";
            case 5:
                return "";
            default:
                break;
        }
        return null;
    }
}
