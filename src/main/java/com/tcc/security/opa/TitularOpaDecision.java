package com.tcc.security.opa;

public class TitularOpaDecision {
    private Long titularId;
    private boolean allow;
    private String reason;

    public TitularOpaDecision() {}

    public TitularOpaDecision(Long titularId, boolean allow, String reason) {
        this.titularId = titularId;
        this.allow = allow;
        this.reason = reason;
    }

    public Long getTitularId() { return titularId; }
    public void setTitularId(Long titularId) { this.titularId = titularId; }
    public boolean isAllow() { return allow; }
    public void setAllow(boolean allow) { this.allow = allow; }
    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }
}
