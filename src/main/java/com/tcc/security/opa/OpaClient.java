package com.tcc.security.opa;

import com.tcc.security.autoconfigure.TccSecurityProperties;
import com.tcc.security.context.AuthorizationContext;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;

public class OpaClient {

    private final TccSecurityProperties.OpaProperties opaProperties;
    private final RestClient restClient;

    public OpaClient(TccSecurityProperties.OpaProperties opaProperties) {
        this(opaProperties, RestClient.builder()
                .baseUrl(opaProperties.getUrl())
                .build());
    }

    OpaClient(TccSecurityProperties.OpaProperties opaProperties, RestClient restClient) {
        this.opaProperties = opaProperties;
        this.restClient = restClient;
    }

    public OpaDecision evaluate(AuthorizationContext context) {
        try {
            OpaRequest request = new OpaRequest();
            request.setInput(context);

            OpaResponse response = restClient.post()
                    .uri("")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(request)
                    .retrieve()
                    .body(OpaResponse.class);

            if (response != null && response.getResult() != null) {
                return response.getResult();
            }
            return denied("OPA returned empty response");
        } catch (Exception e) {
            System.out.println("[TCC-Security] OPA error: " + e.getMessage());
            return denied("OPA communication error: " + e.getMessage());
        }
    }

    public OpaDecision denied(String reason) {
        OpaDecision decision = new OpaDecision();
        decision.setAllow(false);
        decision.setReason(reason);
        return decision;
    }

    static class OpaResponse {
        private OpaDecision result;

        public OpaDecision getResult() {
            return result;
        }

        public void setResult(OpaDecision result) {
            this.result = result;
        }
    }
}
