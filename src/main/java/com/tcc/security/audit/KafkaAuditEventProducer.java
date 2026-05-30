package com.tcc.security.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;

import java.util.concurrent.CompletableFuture;

public class KafkaAuditEventProducer implements AuditEventProducer {

    private static final Logger log = LoggerFactory.getLogger(KafkaAuditEventProducer.class);
    private static final String TOPIC = "ev-audit-authorizations";

    private final KafkaTemplate<String, AuditEvent> kafkaTemplate;

    public KafkaAuditEventProducer(KafkaTemplate<String, AuditEvent> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
    }

    @Override
    public void sendEvent(AuditEvent event) {
        try {
            String key = event.getCorrelationId() != null ? event.getCorrelationId() : event.getCallerClientId();
            CompletableFuture<SendResult<String, AuditEvent>> future = kafkaTemplate.send(TOPIC, key, event);
            future.whenComplete((result, ex) -> {
                if (ex != null) {
                    log.warn("Failed to send audit event to Kafka: {}", ex.getMessage());
                }
            });
        } catch (Exception e) {
            log.warn("Failed to send audit event to Kafka: {}", e.getMessage());
        }
    }
}
