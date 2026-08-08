package com.tcc.security.autoconfigure;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.tcc.security.audit.AuditEvent;
import com.tcc.security.audit.AuditEventProducer;
import com.tcc.security.audit.KafkaAuditEventProducer;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.serializer.JsonSerializer;

import java.util.HashMap;
import java.util.Map;

@AutoConfiguration
@AutoConfigureBefore(TccSecurityAutoConfiguration.class)
@ConditionalOnClass(KafkaTemplate.class)
@ConditionalOnProperty(name = "tcc.security.audit.kafka.enabled", havingValue = "true", matchIfMissing = false)
public class KafkaAuditAutoConfiguration {

    @Bean
    @Primary
    public AuditEventProducer kafkaAuditEventProducer(
            KafkaTemplate<String, AuditEvent> auditKafkaTemplate,
            @Qualifier("auditDltKafkaTemplate") KafkaTemplate<String, AuditEvent> auditDltKafkaTemplate) {
        return new KafkaAuditEventProducer(auditKafkaTemplate, auditDltKafkaTemplate);
    }

    @Bean
    @Primary
    public KafkaTemplate<String, AuditEvent> auditKafkaTemplate(
            @Value("${spring.kafka.bootstrap-servers:localhost:9092}") String bootstrapServers) {

        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);

        JsonSerializer<AuditEvent> valueSerializer = new JsonSerializer<>(objectMapper);
        valueSerializer.setAddTypeInfo(false);

        Map<String, Object> props = new HashMap<>();
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ProducerConfig.RETRIES_CONFIG, 10);
        props.put(ProducerConfig.ACKS_CONFIG, "all");
        props.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, true);

        DefaultKafkaProducerFactory<String, AuditEvent> factory =
                new DefaultKafkaProducerFactory<>(props);
        factory.setKeySerializerSupplier(StringSerializer::new);
        factory.setValueSerializerSupplier(() -> valueSerializer);
        return new KafkaTemplate<>(factory);
    }

    @Bean
    public KafkaTemplate<String, AuditEvent> auditDltKafkaTemplate(
            @Value("${spring.kafka.bootstrap-servers:localhost:9092}") String bootstrapServers) {

        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);

        JsonSerializer<AuditEvent> valueSerializer = new JsonSerializer<>(objectMapper);
        valueSerializer.setAddTypeInfo(false);

        Map<String, Object> props = new HashMap<>();
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ProducerConfig.RETRIES_CONFIG, 3);
        props.put(ProducerConfig.ACKS_CONFIG, "all");

        DefaultKafkaProducerFactory<String, AuditEvent> factory =
                new DefaultKafkaProducerFactory<>(props);
        factory.setKeySerializerSupplier(StringSerializer::new);
        factory.setValueSerializerSupplier(() -> valueSerializer);
        return new KafkaTemplate<>(factory);
    }

    @Bean
    public NewTopic auditTopic() {
        return new NewTopic("ev-audit-authorizations", 3, (short) 1);
    }

    @Bean
    public NewTopic auditDltTopic() {
        return new NewTopic("ev-audit-authorizations-dlt", 1, (short) 1);
    }
}
