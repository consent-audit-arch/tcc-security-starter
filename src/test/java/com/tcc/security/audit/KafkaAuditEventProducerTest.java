package com.tcc.security.audit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;

import java.time.Instant;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class KafkaAuditEventProducerTest {

    @Mock
    private KafkaTemplate<String, AuditEvent> kafkaTemplate;

    @InjectMocks
    private KafkaAuditEventProducer producer;

    @Test
    void sendEventShouldNotThrowWhenKafkaIsAvailable() {
        var event = createTestEvent();
        when(kafkaTemplate.send(eq("ev-audit-authorizations"), eq("corr-123"), eq(event)))
                .thenReturn(CompletableFuture.completedFuture(null));

        assertThatCode(() -> producer.sendEvent(event)).doesNotThrowAnyException();
    }

    @Test
    void sendEventShouldNotThrowWhenKafkaTemplateThrowsSynchronously() {
        var event = createTestEvent();
        when(kafkaTemplate.send(any(), any(), any()))
                .thenThrow(new RuntimeException("Kafka unavailable"));

        assertThatCode(() -> producer.sendEvent(event)).doesNotThrowAnyException();
    }

    @Test
    void sendEventShouldNotThrowWhenFutureCompletesExceptionally() {
        var event = createTestEvent();
        CompletableFuture<SendResult<String, AuditEvent>> failedFuture = new CompletableFuture<>();
        failedFuture.completeExceptionally(new RuntimeException("Broker unavailable"));

        when(kafkaTemplate.send(eq("ev-audit-authorizations"), eq("corr-123"), eq(event)))
                .thenReturn(failedFuture);

        assertThatCode(() -> producer.sendEvent(event)).doesNotThrowAnyException();
    }

    @Test
    void sendEventShouldNotThrowWhenCorrelationIdIsNull() {
        var event = new AuditEvent(Instant.now(), "client1", "sub1", Set.of("USER_READ"),
                "USER_USAGE", "READ", "PROMOTION", "100", null,
                java.util.List.of("USAGE_DATA"), null, "GET", "/api/v1/users/100/usage",
                true, "Access granted");

        when(kafkaTemplate.send(eq("ev-audit-authorizations"), eq("client1"), eq(event)))
                .thenReturn(CompletableFuture.completedFuture(null));

        assertThatCode(() -> producer.sendEvent(event)).doesNotThrowAnyException();
    }

    @Test
    void sendEventShouldNotThrowWhenEventIsNull() {
        assertThatCode(() -> producer.sendEvent(null)).doesNotThrowAnyException();
    }

    private AuditEvent createTestEvent() {
        return new AuditEvent(Instant.now(), "client1", "sub1", Set.of("USER_READ"),
                "USER_USAGE", "READ", "PROMOTION", "100", null,
                java.util.List.of("USAGE_DATA"), "corr-123", "GET", "/api/v1/users/100/usage",
                true, "Access granted");
    }
}
