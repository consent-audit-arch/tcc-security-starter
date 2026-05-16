package com.tcc.security.context;

import java.util.List;

public class AuthorizationContext {
    private CallerIdentity caller;
    private String resource;
    private String action;
    private String purpose;
    private String dataSubjectId;
    private String dataCategory;
    private List<String> dataCategories;
    private String correlationId;
    private String httpMethod;
    private String path;

    public CallerIdentity getCaller() { return caller; }
    public void setCaller(CallerIdentity caller) { this.caller = caller; }
    public String getResource() { return resource; }
    public void setResource(String resource) { this.resource = resource; }
    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }
    public String getPurpose() { return purpose; }
    public void setPurpose(String purpose) { this.purpose = purpose; }
    public String getDataSubjectId() { return dataSubjectId; }
    public void setDataSubjectId(String dataSubjectId) { this.dataSubjectId = dataSubjectId; }
    public String getDataCategory() { return dataCategory; }
    public void setDataCategory(String dataCategory) { this.dataCategory = dataCategory; }
    public List<String> getDataCategories() { return dataCategories; }
    public void setDataCategories(List<String> dataCategories) { this.dataCategories = dataCategories; }
    public String getCorrelationId() { return correlationId; }
    public void setCorrelationId(String correlationId) { this.correlationId = correlationId; }
    public String getHttpMethod() { return httpMethod; }
    public void setHttpMethod(String httpMethod) { this.httpMethod = httpMethod; }
    public String getPath() { return path; }
    public void setPath(String path) { this.path = path; }
}
