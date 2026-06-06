package com.tcc.security.opa;

import com.tcc.security.autoconfigure.TccSecurityProperties;
import com.tcc.security.context.AuthorizationContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

class OpaClientTest {

    private OpaClient opaClient;
    private MockRestServiceServer mockServer;

    @BeforeEach
    void setUp() {
        var opaProperties = new TccSecurityProperties.OpaProperties();
        opaProperties.setUrl("http://localhost:0/v1/data/test");

        var restTemplate = new RestTemplate();
        mockServer = MockRestServiceServer.bindTo(restTemplate).build();
        var restClient = RestClient.builder(restTemplate).baseUrl(opaProperties.getUrl()).build();
        opaClient = new OpaClient(opaProperties, restClient);
    }

    @Test
    void evaluateShouldReturnAllowWhenOpaAllows() {
        mockServer.expect(requestTo("http://localhost:0/v1/data/test"))
                .andExpect(method(org.springframework.http.HttpMethod.POST))
                .andRespond(withSuccess(
                        "{\"result\":{\"allow\":true,\"reason\":\"Access granted\"}}",
                        MediaType.APPLICATION_JSON));

        var context = new AuthorizationContext();
        context.setResource("USER_USAGE");
        context.setAction("READ");

        OpaDecision result = opaClient.evaluate(context);

        assertThat(result.isAllow()).isTrue();
        assertThat(result.getReason()).isEqualTo("Access granted");
        mockServer.verify();
    }

    @Test
    void evaluateShouldReturnDeniedWhenOpaDenies() {
        mockServer.expect(requestTo("http://localhost:0/v1/data/test"))
                .andExpect(method(org.springframework.http.HttpMethod.POST))
                .andRespond(withSuccess(
                        "{\"result\":{\"allow\":false,\"reason\":\"Active consent not found\"}}",
                        MediaType.APPLICATION_JSON));

        var context = new AuthorizationContext();
        context.setResource("USER_USAGE");
        context.setAction("READ");

        OpaDecision result = opaClient.evaluate(context);

        assertThat(result.isAllow()).isFalse();
        assertThat(result.getReason()).isEqualTo("Active consent not found");
        mockServer.verify();
    }

    @Test
    void evaluateShouldReturnBatchDecisions() {
        mockServer.expect(requestTo("http://localhost:0/v1/data/test"))
                .andExpect(method(org.springframework.http.HttpMethod.POST))
                .andRespond(withSuccess(
                        """
                        {"result":{"allow":true,"reason":"Batch partial success","decisions":[
                            {"titularId":100,"allow":true,"reason":"Access granted"},
                            {"titularId":101,"allow":false,"reason":"CONSENT_NOT_FOUND"}
                        ]}}
                        """,
                        MediaType.APPLICATION_JSON));

        var context = new AuthorizationContext();
        context.setResource("USER_USAGE");
        context.setAction("READ");
        context.setDataSubjectIds(java.util.List.of(100L, 101L));

        OpaDecision result = opaClient.evaluate(context);

        assertThat(result.isAllow()).isTrue();
        assertThat(result.isBatch()).isTrue();
        assertThat(result.getDecisions()).hasSize(2);
        assertThat(result.getDecisions().get(0).isAllow()).isTrue();
        assertThat(result.getDecisions().get(1).isAllow()).isFalse();
        assertThat(result.getDecisions().get(1).getReason()).isEqualTo("CONSENT_NOT_FOUND");
        mockServer.verify();
    }

    @Test
    void evaluateShouldReturnDeniedOn4xx() {
        mockServer.expect(requestTo("http://localhost:0/v1/data/test"))
                .andExpect(method(org.springframework.http.HttpMethod.POST))
                .andRespond(withBadRequest().body("Bad request"));

        var context = new AuthorizationContext();
        context.setResource("USER_USAGE");
        context.setAction("READ");

        OpaDecision result = opaClient.evaluate(context);

        assertThat(result.isAllow()).isFalse();
        assertThat(result.getReason()).contains("OPA communication error");
        mockServer.verify();
    }

    @Test
    void evaluateShouldReturnDeniedOn5xx() {
        mockServer.expect(requestTo("http://localhost:0/v1/data/test"))
                .andExpect(method(org.springframework.http.HttpMethod.POST))
                .andRespond(withServerError().body("Internal error"));

        var context = new AuthorizationContext();
        context.setResource("USER_USAGE");
        context.setAction("READ");

        OpaDecision result = opaClient.evaluate(context);

        assertThat(result.isAllow()).isFalse();
        assertThat(result.getReason()).contains("OPA communication error");
        mockServer.verify();
    }

    @Test
    void evaluateShouldReturnDeniedOnEmptyResponse() {
        mockServer.expect(requestTo("http://localhost:0/v1/data/test"))
                .andExpect(method(org.springframework.http.HttpMethod.POST))
                .andRespond(withSuccess("{}", MediaType.APPLICATION_JSON));

        var context = new AuthorizationContext();
        context.setResource("USER_USAGE");
        context.setAction("READ");

        OpaDecision result = opaClient.evaluate(context);

        assertThat(result.isAllow()).isFalse();
        assertThat(result.getReason()).contains("OPA returned empty response");
        mockServer.verify();
    }

    @Test
    void evaluateShouldReturnDeniedOnMalformedJson() {
        mockServer.expect(requestTo("http://localhost:0/v1/data/test"))
                .andExpect(method(org.springframework.http.HttpMethod.POST))
                .andRespond(withSuccess("not json", MediaType.APPLICATION_JSON));

        var context = new AuthorizationContext();
        context.setResource("USER_USAGE");
        context.setAction("READ");

        OpaDecision result = opaClient.evaluate(context);

        assertThat(result.isAllow()).isFalse();
        assertThat(result.getReason()).contains("OPA communication error");
        mockServer.verify();
    }

    @Test
    void evaluateShouldReturnDeniedOnNullResult() {
        mockServer.expect(requestTo("http://localhost:0/v1/data/test"))
                .andExpect(method(org.springframework.http.HttpMethod.POST))
                .andRespond(withSuccess(
                        "{\"result\":null}",
                        MediaType.APPLICATION_JSON));

        var context = new AuthorizationContext();
        context.setResource("USER_USAGE");
        context.setAction("READ");

        OpaDecision result = opaClient.evaluate(context);

        assertThat(result.isAllow()).isFalse();
        assertThat(result.getReason()).contains("OPA returned empty response");
        mockServer.verify();
    }

    @Test
    void deniedShouldCreateDeniedDecision() {
        OpaDecision result = opaClient.denied("Custom reason");

        assertThat(result.isAllow()).isFalse();
        assertThat(result.getReason()).isEqualTo("Custom reason");
    }
}
