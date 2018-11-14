package io.bitwise.sawtooth_xo.state.rest_api;

/**
 * Data class for interacting with the Sawtooth REST Api
 */
public final class BatchListResponse {

    private String link;
    private Integer code;
    private String title;
    private String message;

    /** Returns the link to query the batch status
     *
     * @return String link
     */
    public final String getLink() {
        return link;
    }

    /**
     * Returns the error code if there is one.
     *
     * @return Integer code
     */
    public final Integer getCode() {
        return code;
    }

    /**
     * Returns a short summary title describing the error.
     *
     * @return String title
     */
    public final String getTitle() {
        return title;
    }

    /**
     * Returns a longer message explaining the error.
     *
     * @return String message
     */
    public final String getMessage() {
        return message;
    }
}
