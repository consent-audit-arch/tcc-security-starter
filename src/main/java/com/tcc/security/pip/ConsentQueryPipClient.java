package com.tcc.security.pip;

import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;

import java.util.Collections;
import java.util.List;

public class ConsentQueryPipClient {

    private final RestClient restClient;

    public ConsentQueryPipClient(String pipUrl) {
        this.restClient = RestClient.builder()
                .baseUrl(pipUrl)
                .build();
    }

    public PipBatchResponse batchAuthorizations(List<Long> titularIds, String dataCategory, String purpose) {
        try {
            PipBatchRequest request = new PipBatchRequest(titularIds, dataCategory, purpose);

            return restClient.post()
                    .uri("/batch/authorizations")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(request)
                    .retrieve()
                    .body(PipBatchResponse.class);
        } catch (Exception e) {
            System.out.println("[TCC-Security] PIP error: " + e.getMessage());
            PipBatchResponse fallback = new PipBatchResponse();
            fallback.setResults(titularIds.stream()
                    .map(id -> new PipTitularResult(id, false, "PIP_UNAVAILABLE"))
                    .toList());
            return fallback;
        }
    }

    public List<PipTitularResult> batchAuthorizationsResult(List<Long> titularIds, String dataCategory, String purpose) {
        PipBatchResponse response = batchAuthorizations(titularIds, dataCategory, purpose);
        if (response != null && response.getResults() != null) {
            return response.getResults();
        }
        return Collections.emptyList();
    }
}
