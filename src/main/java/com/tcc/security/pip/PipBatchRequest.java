package com.tcc.security.pip;

import java.util.List;

public class PipBatchRequest {
    private List<Long> titularIds;
    private String dataCategory;
    private String purpose;

    public PipBatchRequest() {}

    public PipBatchRequest(List<Long> titularIds, String dataCategory, String purpose) {
        this.titularIds = titularIds;
        this.dataCategory = dataCategory;
        this.purpose = purpose;
    }

    public List<Long> getTitularIds() { return titularIds; }
    public void setTitularIds(List<Long> titularIds) { this.titularIds = titularIds; }
    public String getDataCategory() { return dataCategory; }
    public void setDataCategory(String dataCategory) { this.dataCategory = dataCategory; }
    public String getPurpose() { return purpose; }
    public void setPurpose(String purpose) { this.purpose = purpose; }
}
