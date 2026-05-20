package com.tcc.security.opa;

import java.util.List;

public class OpaDecision {
    private boolean allow;
    private String reason;
    private List<TitularOpaDecision> decisions;

    public boolean isAllow() {
        return allow;
    }

    public void setAllow(boolean allow) {
        this.allow = allow;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public List<TitularOpaDecision> getDecisions() {
        return decisions;
    }

    public void setDecisions(List<TitularOpaDecision> decisions) {
        this.decisions = decisions;
    }

    public boolean isBatch() {
        return decisions != null && !decisions.isEmpty();
    }
}
