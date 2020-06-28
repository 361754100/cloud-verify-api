package com.hro.core.cloudverifyapi.response;

/**
 * 分页检索
 */
public class PageSearchWrapper extends CommonWrapper {

    private int totalCount;

    private int pageNo;

    private Object records;

    public int getTotalCount() {
        return totalCount;
    }

    public void setTotalCount(int totalCount) {
        this.totalCount = totalCount;
    }

    public int getPageNo() {
        return pageNo;
    }

    public void setPageNo(int pageNo) {
        this.pageNo = pageNo;
    }

    public Object getRecords() {
        return records;
    }

    public void setRecords(Object records) {
        this.records = records;
    }
}
