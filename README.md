# TCC Security Starter

Biblioteca reutilizável para padronização de autenticação M2M, autorização contextual e rastreabilidade no Módulo 2 do projeto TCC SQUAD.

## Objetivo

O `tcc-security-starter` atua como **PEP (Policy Enforcement Point)** embutido em cada serviço protegido, integrando-se com:
- **Keycloak** para autenticação M2M via `client_credentials`
- **OPA** (como sidecar local) para decisão de autorização contextual
- **Spring Security** como base de validação JWT

## Arquitetura

```
Serviço → [Spring Security JWT] → [ConsentAuthorizationAspect] → [OPA sidecar] → Decisão
```

- Keycloak autentica o serviço chamador (M2M)
- OPA decide autorização considerando: serviço, finalidade, recurso, titular e consentimento
- Princípio **fail closed**: erro de comunicação com OPA nega acesso

## Uso nos Serviços Consumidores

### Dependência Maven

```xml
<dependency>
    <groupId>com.tcc</groupId>
    <artifactId>tcc-security-starter</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

### application.yml

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://localhost:8180/realms/tcc

tcc:
  security:
    enabled: true
    opa:
      enabled: true
      url: http://localhost:8181/v1/data/user/authz/decision
      timeout: 2s
    headers:
      purpose: X-Purpose
      data-subject-id: X-Data-Subject-Id
      correlation-id: X-Correlation-Id
```

### Exemplo de Uso da Annotation

```java
@RestController
public class UserController {

    @RequiresConsent(resource = "USER_PROFILE", action = "READ")
    @GetMapping("/{id}")
    public UserResponse findById(@PathVariable Long id) {
        return userService.findById(id);
    }
}
```

### Headers Esperados em Chamadas Protegidas

```
Authorization: Bearer <token-client-credentials>
X-Purpose: BILLING_ANALYSIS
X-Data-Subject-Id: <id-do-titular>
X-Correlation-Id: <uuid>
```

### Exemplo de Chamada M2M

1. Obter token no Keycloak:
```bash
curl -X POST http://localhost:8180/realms/tcc/protocol/openid-connect/token \
  -u "billing-service:client-secret" \
  -d "grant_type=client_credentials"
```

2. Chamar serviço protegido:
```bash
curl http://localhost:8080/users/123 \
  -H "Authorization: Bearer <token>" \
  -H "X-Purpose: BILLING_ANALYSIS" \
  -H "X-Data-Subject-Id: 123" \
  -H "X-Correlation-Id: $(uuidgen)"
```

## Componentes

| Classe | Papel |
|--------|-------|
| `@RequiresConsent` | Annotation para marcar métodos que exigem autorização |
| `ConsentAuthorizationAspect` | Aspect que intercepta e valida acesso via OPA |
| `OpaClient` | Cliente REST para OPA sidecar (fail closed) |
| `AuthorizationContext` | Modelo de contexto enviado ao OPA |
| `TccSecurityProperties` | Configurações via `tcc.security.*` |
| `DataAccessDeniedException` | Exceção lançada quando OPA nega acesso |

## Build

```bash
mvn clean install
```

## Notas

- Não inclui Kafka (auditoria será adicionada futuramente)
- Não inclui integração com consent-query-service (será PIP futuro)
- Foco exclusivo em M2M com `client_credentials`
- OPA deve rodar como sidecar no mesmo pod/container network
