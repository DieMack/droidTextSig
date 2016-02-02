package com.xpandit.signature;

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
    NOT_ENOUGH_SPACE(3);

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
            default:
                break;
        }
        return null;
    }
}
