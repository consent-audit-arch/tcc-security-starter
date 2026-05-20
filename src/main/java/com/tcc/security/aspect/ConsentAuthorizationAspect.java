package com.tcc.security.aspect;

import com.tcc.security.annotation.RequiresConsent;
import com.tcc.security.autoconfigure.TccSecurityProperties;
import com.tcc.security.context.AuthorizationContext;
import com.tcc.security.context.CallerIdentity;
import com.tcc.security.exception.DataAccessDeniedException;
import com.tcc.security.opa.OpaClient;
import com.tcc.security.opa.OpaDecision;
import com.tcc.security.pip.ConsentQueryPipClient;
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
    private final ConsentQueryPipClient pipClient;

    public ConsentAuthorizationAspect(TccSecurityProperties properties, OpaClient opaClient, ConsentQueryPipClient pipClient) {
        this.properties = properties;
        this.opaClient = opaClient;
        this.pipClient = pipClient;
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

        if (context.isBatchRequest()) {
            return handleBatchRequest(joinPoint, context);
        }

        OpaDecision decision = opaClient.evaluate(context);
        System.out.println("[TCC-Security] Decision: allow=" + decision.isAllow() + " reason=" + decision.getReason());
        if (!decision.isAllow()) {
            throw new DataAccessDeniedException(decision.getReason() != null
                    ? decision.getReason()
                    : "Access denied by OPA");
        }

        return joinPoint.proceed();
    }

    private String resolveBatchDataCategory(AuthorizationContext context) {
        List<String> categories = context.getDataCategories();
        if (categories != null && !categories.isEmpty()) {
            return categories.get(0);
        }
        return context.getDataCategory();
    }

    private Object handleBatchRequest(ProceedingJoinPoint joinPoint, AuthorizationContext context) throws Throwable {
        List<PipTitularResult> pipResults = pipClient.batchAuthorizationsResult(
                context.getDataSubjectIds(),
                resolveBatchDataCategory(context),
                context.getPurpose());

        context.setPipData(pipResults);

        OpaDecision decision = opaClient.evaluate(context);
        System.out.println("[TCC-Security] Batch decision: allow=" + decision.isAllow());

        if (!decision.isAllow()) {
            throw new DataAccessDeniedException("All titulars denied");
        }

        List<PipTitularResult> decisions = pipResults;
        if (decision.isBatch()) {
            decisions = decision.getDecisions().stream()
                    .map(d -> new PipTitularResult(d.getTitularId(), d.isAllow(), d.getReason()))
                    .toList();
        }

        HttpServletRequest request = getCurrentRequest();
        if (request != null) {
            request.setAttribute(DECISIONS_ATTR, decisions);
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
            String dataCategory = request.getHeader(properties.getHeaders().getDataCategory());
            if (dataCategory == null) {
                dataCategory = request.getHeader(properties.getHeaders().getDataCategories());
            }
            context.setDataCategory(dataCategory);
            context.setCorrelationId(request.getHeader(properties.getHeaders().getCorrelationId()));
            context.setHttpMethod(request.getMethod());
            context.setPath(request.getRequestURI());

            String dataSubjectIdsHeader = request.getHeader(properties.getHeaders().getDataSubjectIds());
            if (dataSubjectIdsHeader != null && !dataSubjectIdsHeader.isBlank()) {
                List<Long> ids = Arrays.stream(dataSubjectIdsHeader.split(","))
                        .map(String::trim)
                        .filter(s -> !s.isEmpty())
                        .map(Long::valueOf)
                        .toList();
                context.setDataSubjectIds(ids);
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
}
