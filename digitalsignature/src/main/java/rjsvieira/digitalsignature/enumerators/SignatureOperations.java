package rjsvieira.digitalsignature.enumerators;

/**
 * Description
 *
 * @author <a href="mailto:rvfts@hotmail.com">RJSV</a>
 * @version $Revision : 1 $
 */

public enum SignatureOperations {

    MANUAL_SIGNATURE(0),
    DIGITAL_SIGNATURE(1),
    TIMESTAMPING(2);

    private int position;

    SignatureOperations(int n) {
        position = n;
    }

    public static SignatureOperations match(int n) {
        switch (n) {
            case -1:
                return MANUAL_SIGNATURE;
            case 0:
                return DIGITAL_SIGNATURE;
            case 1:
                return TIMESTAMPING;
            default:
                break;
        }
        return null;
    }

}
