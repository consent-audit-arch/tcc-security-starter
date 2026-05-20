package com.tcc.security.pip;

import java.util.List;

public class PipBatchResponse {
    private List<PipTitularResult> results;

    public PipBatchResponse() {}

    public PipBatchResponse(List<PipTitularResult> results) {
        this.results = results;
    }

    public List<PipTitularResult> getResults() { return results; }
    public void setResults(List<PipTitularResult> results) { this.results = results; }
}
