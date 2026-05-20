package com.tcc.security.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.time.Duration;

@ConfigurationProperties(prefix = "tcc.security")
public class TccSecurityProperties {

    private boolean enabled = true;

    @NestedConfigurationProperty
    private Headers headers = new Headers();

    @NestedConfigurationProperty
    private OpaProperties opa = new OpaProperties();

    @NestedConfigurationProperty
    private PipProperties pip = new PipProperties();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Headers getHeaders() {
        return headers;
    }

    public void setHeaders(Headers headers) {
        this.headers = headers;
    }

    public OpaProperties getOpa() {
        return opa;
    }

    public void setOpa(OpaProperties opa) {
        this.opa = opa;
    }

    public PipProperties getPip() {
        return pip;
    }

    public void setPip(PipProperties pip) {
        this.pip = pip;
    }

    public static class Headers {
        private String purpose = "X-Purpose";
        private String dataSubjectId = "X-Data-Subject-Id";
        private String dataSubjectIds = "X-Data-Subject-Ids";
        private String correlationId = "X-Correlation-Id";
        private String dataCategory = "X-Data-Category";
        private String dataCategories = "X-Data-Categories";

        public String getPurpose() { return purpose; }
        public void setPurpose(String purpose) { this.purpose = purpose; }
        public String getDataSubjectId() { return dataSubjectId; }
        public void setDataSubjectId(String dataSubjectId) { this.dataSubjectId = dataSubjectId; }
        public String getDataSubjectIds() { return dataSubjectIds; }
        public void setDataSubjectIds(String dataSubjectIds) { this.dataSubjectIds = dataSubjectIds; }
        public String getCorrelationId() { return correlationId; }
        public void setCorrelationId(String correlationId) { this.correlationId = correlationId; }
        public String getDataCategory() { return dataCategory; }
        public void setDataCategory(String dataCategory) { this.dataCategory = dataCategory; }
        public String getDataCategories() { return dataCategories; }
        public void setDataCategories(String dataCategories) { this.dataCategories = dataCategories; }
    }

    public static class OpaProperties {
        private boolean enabled = true;
        private String url = "http://localhost:8181/v1/data/authz/decision";
        private Duration timeout = Duration.ofSeconds(2);

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }

        public Duration getTimeout() {
            return timeout;
        }

        public void setTimeout(Duration timeout) {
            this.timeout = timeout;
        }
    }

    public static class PipProperties {
        private String url = "http://localhost:8080/api/v1/consent";

        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
    }
}
