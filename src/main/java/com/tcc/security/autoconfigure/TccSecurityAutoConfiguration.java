package com.tcc.security.autoconfigure;

import com.tcc.security.aspect.ConsentAuthorizationAspect;
import com.tcc.security.audit.AuditEventProducer;
import com.tcc.security.audit.NoopAuditEventProducer;
import com.tcc.security.opa.OpaClient;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@AutoConfiguration
@EnableConfigurationProperties(TccSecurityProperties.class)
public class TccSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(OpaClient.class)
    public OpaClient opaClient(TccSecurityProperties properties) {
        return new OpaClient(properties.getOpa());
    }

    @Bean
    @ConditionalOnMissingBean(AuditEventProducer.class)
    public AuditEventProducer noopAuditEventProducer() {
        return new NoopAuditEventProducer();
    }

    @Bean
    @ConditionalOnProperty(name = "tcc.security.enabled", havingValue = "true", matchIfMissing = true)
    public ConsentAuthorizationAspect consentAuthorizationAspect(
            TccSecurityProperties properties,
            OpaClient opaClient,
            AuditEventProducer auditEventProducer) {
        return new ConsentAuthorizationAspect(properties, opaClient, auditEventProducer);
    }

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/health").permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        return http.build();
    }
}
