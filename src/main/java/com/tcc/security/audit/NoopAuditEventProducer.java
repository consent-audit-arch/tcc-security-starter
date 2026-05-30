package com.tcc.security.audit;

public class NoopAuditEventProducer implements AuditEventProducer {
    @Override
    public void sendEvent(AuditEvent event) {
    }
}
