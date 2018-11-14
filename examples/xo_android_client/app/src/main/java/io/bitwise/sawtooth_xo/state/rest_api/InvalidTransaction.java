package io.bitwise.sawtooth_xo.state.rest_api;

/**
 * Data class for InvalidTransaction within a batch Status.
 *
 */
public final class InvalidTransaction {
    private String id;
    private String message;
    private String extendedData;

    /**
     * The transaction Id.
     *
     * @return String id
     */
    public String getId() {
        return id;
    }

    /**
     * The message giving the TP generated reason for transaction failure.
     *
     * @return String message
     */
    public String getMessage() {
        return message;
    }

    /**
     * The extended data, base64 encoded bytes, associated with the transaction failure.
     *
     * @return String extendedData
     */
    public String getExtendedData() {
        return extendedData;
    }
}
