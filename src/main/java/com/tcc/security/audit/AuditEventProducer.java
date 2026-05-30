package com.tcc.security.audit;

public interface AuditEventProducer {
    void sendEvent(AuditEvent event);
}
