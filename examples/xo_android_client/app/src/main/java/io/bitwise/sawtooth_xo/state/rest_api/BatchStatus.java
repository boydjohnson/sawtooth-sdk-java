package io.bitwise.sawtooth_xo.state.rest_api;

import java.util.List;

public final class BatchStatus {
    private String id;
    private String status;
    private List<InvalidTransaction> invalidTransactions;
    private String link;

    /**
     * The 
     *
     * @return
     */
    public String getId() {
        return id;
    }

    public String getStatus() {
        return status;
    }

    public List<InvalidTransaction> getInvalidTransactions() {
        return invalidTransactions;
    }

    public String getLink() {
        return link;
    }
}