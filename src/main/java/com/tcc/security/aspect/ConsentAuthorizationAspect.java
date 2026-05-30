package com.tcc.security.aspect;

import com.tcc.security.annotation.RequiresConsent;
import com.tcc.security.audit.AuditEvent;
import com.tcc.security.audit.AuditEventProducer;
import com.tcc.security.autoconfigure.TccSecurityProperties;
import com.tcc.security.context.AuthorizationContext;
import com.tcc.security.context.CallerIdentity;
import com.tcc.security.exception.DataAccessDeniedException;
import com.tcc.security.opa.OpaClient;
import com.tcc.security.opa.OpaDecision;
import com.tcc.security.opa.TitularOpaDecision;
import com.tcc.security.pip.PipTitularResult;
import jakarta.servlet.http.HttpServletRequest;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.core.DefaultParameterNameDiscoverer;
import org.springframework.core.ParameterNameDiscoverer;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Aspect
public class ConsentAuthorizationAspect {

    private static final String DECISIONS_ATTR = "tcc-authorization-decisions";

    private final TccSecurityProperties properties;
    private final OpaClient opaClient;
    private final AuditEventProducer auditEventProducer;
    private final ParameterNameDiscoverer parameterNameDiscoverer;

    public ConsentAuthorizationAspect(TccSecurityProperties properties, OpaClient opaClient,
                                      AuditEventProducer auditEventProducer) {
        this.properties = properties;
        this.opaClient = opaClient;
        this.auditEventProducer = auditEventProducer;
        this.parameterNameDiscoverer = new DefaultParameterNameDiscoverer();
    }

    @Around("@annotation(requiresConsent)")
    public Object authorize(ProceedingJoinPoint joinPoint, RequiresConsent requiresConsent) throws Throwable {
        System.out.println("[TCC-Security] Aspect triggered");

        if (!properties.isEnabled()) {
            System.out.println("[TCC-Security] properties.enabled=" + properties.isEnabled());
            return joinPoint.proceed();
        }

        AuthorizationContext context = buildContext(joinPoint, requiresConsent);
        logContext(context);

        if (!properties.getOpa().isEnabled()) {
            System.out.println("[TCC-Security] opa.enabled=" + properties.getOpa().isEnabled());
            return joinPoint.proceed();
        }

        if (context.isBatchRequest()) {
            return handleBatchRequest(joinPoint, context);
        }

        OpaDecision decision = opaClient.evaluate(context);
        System.out.println("[TCC-Security] Decision: allow=" + decision.isAllow() + " reason=" + decision.getReason());

        sendAuditEvent(context, decision.isAllow(), decision.getReason());

        if (!decision.isAllow()) {
            throw new DataAccessDeniedException(decision.getReason() != null
                    ? decision.getReason()
                    : "Access denied by OPA");
        }

        return joinPoint.proceed();
    }

    private Object handleBatchRequest(ProceedingJoinPoint joinPoint, AuthorizationContext context) throws Throwable {
        OpaDecision decision = opaClient.evaluate(context);
        System.out.println("[TCC-Security] Batch decision: allow=" + decision.isAllow());

        if (!decision.isAllow()) {
            sendAuditEvent(context, false, decision.getReason());
            String reason = decision.getReason() != null ? decision.getReason() : "All titulars denied";
            throw new DataAccessDeniedException(reason);
        }

        if (decision.isBatch()) {
            List<PipTitularResult> decisions = decision.getDecisions().stream()
                    .map(d -> new PipTitularResult(d.getTitularId(), d.isAllow(), d.getReason()))
                    .toList();
            HttpServletRequest request = getCurrentRequest();
            if (request != null) {
                request.setAttribute(DECISIONS_ATTR, decisions);
            }
            for (PipTitularResult d : decisions) {
                AuditEvent event = buildAuditEvent(context, d.isAuthorized(), d.getReason());
                event.setDataSubjectId(String.valueOf(d.getTitularId()));
                auditEventProducer.sendEvent(event);
            }
        }

        return joinPoint.proceed();
    }

    @SuppressWarnings("unchecked")
    public static List<PipTitularResult> getDecisionsFromRequest() {
        var attributes = RequestContextHolder.getRequestAttributes();
        if (attributes instanceof ServletRequestAttributes servletAttributes) {
            Object attr = servletAttributes.getRequest().getAttribute(DECISIONS_ATTR);
            if (attr instanceof List<?>) {
                return (List<PipTitularResult>) attr;
            }
        }
        return Collections.emptyList();
    }

    private AuthorizationContext buildContext(ProceedingJoinPoint joinPoint, RequiresConsent requiresConsent) {
        AuthorizationContext context = new AuthorizationContext();
        context.setResource(requiresConsent.resource());
        context.setAction(requiresConsent.action());

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof Jwt jwt) {
            context.setCaller(extractCallerIdentity(jwt));
        }

        HttpServletRequest request = getCurrentRequest();
        if (request != null) {
            context.setPurpose(request.getHeader(properties.getHeaders().getPurpose()));
            String correlationId = request.getHeader(properties.getHeaders().getCorrelationId());
            if (correlationId == null || correlationId.isBlank()) {
                correlationId = java.util.UUID.randomUUID().toString();
            }
            context.setCorrelationId(correlationId);
            String dataCategory = request.getHeader(properties.getHeaders().getDataCategory());
            if (dataCategory == null) {
                dataCategory = request.getHeader(properties.getHeaders().getDataCategories());
            }
            context.setDataCategory(dataCategory);
            context.setHttpMethod(request.getMethod());
            context.setPath(request.getRequestURI());

            String dataSubjectId = extractRequiredParam(joinPoint, requiresConsent.dataSubjectIdParam());
            if (dataSubjectId == null) {
                dataSubjectId = request.getHeader(properties.getHeaders().getDataSubjectId());
            }
            context.setDataSubjectId(dataSubjectId);

            String dataSubjectIdsParam = requiresConsent.dataSubjectIdsParam();
            if (!dataSubjectIdsParam.isEmpty()) {
                Object idsValue = extractParamValue(joinPoint, dataSubjectIdsParam);
                if (idsValue instanceof List<?> ids) {
                    List<Long> longIds = ids.stream()
                            .filter(e -> e instanceof Number)
                            .map(e -> ((Number) e).longValue())
                            .toList();
                    if (!longIds.isEmpty()) {
                        context.setDataSubjectIds(longIds);
                    }
                }
            } else {
                String dataSubjectIdsHeader = request.getHeader(properties.getHeaders().getDataSubjectIds());
                if (dataSubjectIdsHeader != null && !dataSubjectIdsHeader.isBlank()) {
                    List<Long> ids = Arrays.stream(dataSubjectIdsHeader.split(","))
                            .map(String::trim)
                            .filter(s -> !s.isEmpty())
                            .map(Long::valueOf)
                            .toList();
                    context.setDataSubjectIds(ids);
                }
            }

            List<String> headerCategories = parseDataCategoriesHeader(
                    request.getHeader(properties.getHeaders().getDataCategories()));
            List<String> annotationCategories = Arrays.asList(requiresConsent.dataCategories());

            if (!annotationCategories.isEmpty()) {
                validateDeclaredCategories(annotationCategories, headerCategories);
                context.setDataCategories(annotationCategories);
            } else {
                context.setDataCategories(headerCategories);
            }
        }

        return context;
    }

    private String extractRequiredParam(ProceedingJoinPoint joinPoint, String paramName) {
        if (paramName == null || paramName.isEmpty()) {
            return null;
        }
        Object value = extractParamValue(joinPoint, paramName);
        if (value == null) {
            return null;
        }
        return String.valueOf(value);
    }

    private Object extractParamValue(ProceedingJoinPoint joinPoint, String paramPath) {
        try {
            MethodSignature signature = (MethodSignature) joinPoint.getSignature();
            String[] paramNames = parameterNameDiscoverer.getParameterNames(signature.getMethod());
            if (paramNames == null) {
                return null;
            }

            String paramName = paramPath.contains(".") ? paramPath.substring(0, paramPath.indexOf('.')) : paramPath;
            String fieldPath = paramPath.contains(".") ? paramPath.substring(paramPath.indexOf('.') + 1) : null;

            Object[] args = joinPoint.getArgs();
            Object paramValue = null;

            for (int i = 0; i < paramNames.length; i++) {
                if (paramNames[i].equals(paramName)) {
                    paramValue = args[i];
                    break;
                }
            }

            if (paramValue == null) {
                return null;
            }

            if (fieldPath != null) {
                return resolveField(paramValue, fieldPath);
            }

            return paramValue;
        } catch (Exception e) {
            System.err.println("[TCC-Security] Failed to extract param: " + paramPath + " - " + e.getMessage());
            return null;
        }
    }

    private Object resolveField(Object target, String fieldPath) throws Exception {
        Object current = target;
        for (String part : fieldPath.split("\\.")) {
            if (current == null) return null;
            String getter = "get" + Character.toUpperCase(part.charAt(0)) + part.substring(1);
            try {
                current = current.getClass().getMethod(getter).invoke(current);
            } catch (NoSuchMethodException e) {
                Field field = current.getClass().getDeclaredField(part);
                field.setAccessible(true);
                current = field.get(current);
            }
        }
        return current;
    }

    private List<String> parseDataCategoriesHeader(String headerValue) {
        if (headerValue == null || headerValue.isBlank()) {
            return Collections.emptyList();
        }
        return Arrays.stream(headerValue.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }

    private void validateDeclaredCategories(List<String> declared, List<String> provided) {
        Set<String> providedSet = new HashSet<>(provided);
        for (String category : declared) {
            if (!providedSet.contains(category)) {
                throw new DataAccessDeniedException(
                        "Required dataCategory '" + category + "' not found in request headers");
            }
        }
    }

    private CallerIdentity extractCallerIdentity(Jwt jwt) {
        CallerIdentity identity = new CallerIdentity();
        identity.setClientId(jwt.getClaimAsString("azp") != null
                ? jwt.getClaimAsString("azp")
                : jwt.getClaimAsString("client_id"));
        identity.setSubject(jwt.getClaimAsString("sub"));
        identity.setIssuer(jwt.getClaimAsString("iss"));

        var realmAccess = jwt.getClaimAsMap("realm_access");
        if (realmAccess != null && realmAccess.get("roles") instanceof Iterable<?> roles) {
            Set<String> roleSet = new java.util.HashSet<>();
            for (Object role : roles) {
                roleSet.add(role.toString());
            }
            identity.setRoles(roleSet);
        }

        return identity;
    }

    private HttpServletRequest getCurrentRequest() {
        var attributes = RequestContextHolder.getRequestAttributes();
        if (attributes instanceof ServletRequestAttributes servletAttributes) {
            return servletAttributes.getRequest();
        }
        return null;
    }

    private void logContext(AuthorizationContext context) {
        if (context.getCaller() != null) {
            System.out.println("[TCC-Security] Caller: " + context.getCaller().getClientId()
                    + " | Resource: " + context.getResource()
                    + " | Action: " + context.getAction()
                    + " | Purpose: " + context.getPurpose()
                    + " | DataCategory: " + context.getDataCategory()
                    + " | Batch: " + context.isBatchRequest()
                    + (context.isBatchRequest() ? " | TitularIds: " + context.getDataSubjectIds() : " | Subject: " + context.getDataSubjectId()));
        }
    }

    private void sendAuditEvent(AuthorizationContext context, boolean allowed, String reason) {
        AuditEvent event = buildAuditEvent(context, allowed, reason);
        auditEventProducer.sendEvent(event);
    }

    private AuditEvent buildAuditEvent(AuthorizationContext context, boolean allowed, String reason) {
        CallerIdentity caller = context.getCaller();
        return new AuditEvent(
                Instant.now(),
                caller != null ? caller.getClientId() : null,
                caller != null ? caller.getSubject() : null,
                caller != null ? caller.getRoles() : null,
                context.getResource(),
                context.getAction(),
                context.getPurpose(),
                context.getDataSubjectId(),
                context.getDataSubjectIds(),
                context.getDataCategories(),
                context.getCorrelationId(),
                context.getHttpMethod(),
                context.getPath(),
                allowed,
                reason
        );
    }
}
