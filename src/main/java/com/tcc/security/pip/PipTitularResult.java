package com.tcc.security.pip;

public class PipTitularResult {
    private Long titularId;
    private boolean authorized;
    private String reason;

    public PipTitularResult() {}

    public PipTitularResult(Long titularId, boolean authorized, String reason) {
        this.titularId = titularId;
        this.authorized = authorized;
        this.reason = reason;
    }

    public Long getTitularId() { return titularId; }
    public void setTitularId(Long titularId) { this.titularId = titularId; }
    public boolean isAuthorized() { return authorized; }
    public void setAuthorized(boolean authorized) { this.authorized = authorized; }
    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }
}
