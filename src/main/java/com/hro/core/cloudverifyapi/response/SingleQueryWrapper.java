package com.hro.core.cloudverifyapi.response;

/**
 * 单个结果检索
 */
public class SingleQueryWrapper extends CommonWrapper {

    private Object record;

    public Object getRecord() {
        return record;
    }

    public void setRecord(Object record) {
        this.record = record;
    }
}
