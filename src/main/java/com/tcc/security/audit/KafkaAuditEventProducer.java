package com.tcc.security.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;

import java.util.concurrent.CompletableFuture;

public class KafkaAuditEventProducer implements AuditEventProducer {

    private static final Logger log = LoggerFactory.getLogger(KafkaAuditEventProducer.class);
    private static final String TOPIC = "ev-audit-authorizations";
    private static final String DLT_TOPIC = "ev-audit-authorizations-dlt";

    private final KafkaTemplate<String, AuditEvent> kafkaTemplate;
    private final KafkaTemplate<String, AuditEvent> dltKafkaTemplate;

    public KafkaAuditEventProducer(KafkaTemplate<String, AuditEvent> kafkaTemplate,
                                    KafkaTemplate<String, AuditEvent> dltKafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
        this.dltKafkaTemplate = dltKafkaTemplate;
    }

    @Override
    public void sendEvent(AuditEvent event) {
        try {
            String key = event.getCorrelationId() != null ? event.getCorrelationId() : event.getCallerClientId();
            CompletableFuture<SendResult<String, AuditEvent>> future = kafkaTemplate.send(TOPIC, key, event);
            future.whenComplete((result, ex) -> {
                if (ex != null) {
                    log.warn("Failed to send audit event after retries, sending to DLT. Key: {}, Error: {}", key, ex.getMessage());
                    sendToDlt(key, event);
                }
            });
        } catch (Exception e) {
            log.warn("Failed to send audit event to Kafka: {}", e.getMessage());
        }
    }

    private void sendToDlt(String key, AuditEvent event) {
        try {
            dltKafkaTemplate.send(DLT_TOPIC, key, event).whenComplete((result, ex) -> {
                if (ex != null) {
                    log.error("Failed to send audit event to DLT as well. Key: {}, Error: {}", key, ex.getMessage());
                } else {
                    log.info("Audit event moved to DLT. Key: {}, CorrelationId: {}", key, event.getCorrelationId());
                }
            });
        } catch (Exception e) {
            log.error("Failed to send audit event to DLT. Key: {}, Error: {}", key, e.getMessage());
        }
    }
}
