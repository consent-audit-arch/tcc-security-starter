package com.tcc.security.audit;

import java.time.Instant;
import java.util.List;
import java.util.Set;

public class AuditEvent {
    private Instant timestamp;
    private String callerClientId;
    private String callerSubject;
    private Set<String> callerRoles;
    private String resource;
    private String action;
    private String purpose;
    private String dataSubjectId;
    private List<Long> dataSubjectIds;
    private List<String> dataCategories;
    private String correlationId;
    private String httpMethod;
    private String path;
    private boolean allowed;
    private String reason;

    public AuditEvent() {}

    public AuditEvent(Instant timestamp, String callerClientId, String callerSubject, Set<String> callerRoles,
                     String resource, String action, String purpose, String dataSubjectId,
                     List<Long> dataSubjectIds, List<String> dataCategories, String correlationId,
                     String httpMethod, String path, boolean allowed, String reason) {
        this.timestamp = timestamp;
        this.callerClientId = callerClientId;
        this.callerSubject = callerSubject;
        this.callerRoles = callerRoles;
        this.resource = resource;
        this.action = action;
        this.purpose = purpose;
        this.dataSubjectId = dataSubjectId;
        this.dataSubjectIds = dataSubjectIds;
        this.dataCategories = dataCategories;
        this.correlationId = correlationId;
        this.httpMethod = httpMethod;
        this.path = path;
        this.allowed = allowed;
        this.reason = reason;
    }

    public Instant getTimestamp() { return timestamp; }
    public void setTimestamp(Instant timestamp) { this.timestamp = timestamp; }
    public String getCallerClientId() { return callerClientId; }
    public void setCallerClientId(String callerClientId) { this.callerClientId = callerClientId; }
    public String getCallerSubject() { return callerSubject; }
    public void setCallerSubject(String callerSubject) { this.callerSubject = callerSubject; }
    public Set<String> getCallerRoles() { return callerRoles; }
    public void setCallerRoles(Set<String> callerRoles) { this.callerRoles = callerRoles; }
    public String getResource() { return resource; }
    public void setResource(String resource) { this.resource = resource; }
    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }
    public String getPurpose() { return purpose; }
    public void setPurpose(String purpose) { this.purpose = purpose; }
    public String getDataSubjectId() { return dataSubjectId; }
    public void setDataSubjectId(String dataSubjectId) { this.dataSubjectId = dataSubjectId; }
    public List<Long> getDataSubjectIds() { return dataSubjectIds; }
    public void setDataSubjectIds(List<Long> dataSubjectIds) { this.dataSubjectIds = dataSubjectIds; }
    public List<String> getDataCategories() { return dataCategories; }
    public void setDataCategories(List<String> dataCategories) { this.dataCategories = dataCategories; }
    public String getCorrelationId() { return correlationId; }
    public void setCorrelationId(String correlationId) { this.correlationId = correlationId; }
    public String getHttpMethod() { return httpMethod; }
    public void setHttpMethod(String httpMethod) { this.httpMethod = httpMethod; }
    public String getPath() { return path; }
    public void setPath(String path) { this.path = path; }
    public boolean isAllowed() { return allowed; }
    public void setAllowed(boolean allowed) { this.allowed = allowed; }
    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }
}
