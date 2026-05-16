package com.tcc.security.aspect;

import com.tcc.security.annotation.RequiresConsent;
import com.tcc.security.autoconfigure.TccSecurityProperties;
import com.tcc.security.context.AuthorizationContext;
import com.tcc.security.context.CallerIdentity;
import com.tcc.security.exception.DataAccessDeniedException;
import com.tcc.security.opa.OpaClient;
import jakarta.servlet.http.HttpServletRequest;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Aspect
public class ConsentAuthorizationAspect {

    private final TccSecurityProperties properties;
    private final OpaClient opaClient;

    public ConsentAuthorizationAspect(TccSecurityProperties properties, OpaClient opaClient) {
        this.properties = properties;
        this.opaClient = opaClient;
    }

    @Around("@annotation(requiresConsent)")
    public Object authorize(ProceedingJoinPoint joinPoint, RequiresConsent requiresConsent) throws Throwable {
        System.out.println("[TCC-Security] Aspect triggered");

        if (!properties.isEnabled()) {
            System.out.println("[TCC-Security] properties.enabled=" + properties.isEnabled());
            return joinPoint.proceed();
        }

        AuthorizationContext context = buildContext(requiresConsent);
        logContext(context);

        if (!properties.getOpa().isEnabled()) {
            System.out.println("[TCC-Security] opa.enabled=" + properties.getOpa().isEnabled());
            return joinPoint.proceed();
        }

        var decision = opaClient.evaluate(context);
        System.out.println("[TCC-Security] Decision: allow=" + decision.isAllow() + " reason=" + decision.getReason());
        if (!decision.isAllow()) {
            throw new DataAccessDeniedException(decision.getReason() != null
                    ? decision.getReason()
                    : "Access denied by OPA");
        }

        return joinPoint.proceed();
    }

    private AuthorizationContext buildContext(RequiresConsent requiresConsent) {
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
            context.setDataSubjectId(request.getHeader(properties.getHeaders().getDataSubjectId()));
            context.setDataCategory(request.getHeader(properties.getHeaders().getDataCategory()));
            context.setCorrelationId(request.getHeader(properties.getHeaders().getCorrelationId()));
            context.setHttpMethod(request.getMethod());
            context.setPath(request.getRequestURI());

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
                    + " | DataCategories: " + context.getDataCategories()
                    + " | Subject: " + context.getDataSubjectId());
        }
    }
}
