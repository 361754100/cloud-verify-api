package com.hro.core.cloudverifyapi.response;

import java.util.List;

/**
 * 多个结果检索
 */
public class ListQueryWrapper<T> extends CommonWrapper {

    private List<T> records;

    public List<T> getRecords() {
        return records;
    }

    public void setRecords(List<T> records) {
        this.records = records;
    }

    @Override
    public String toString() {
        return "ListQueryWrapper{" +
                "records=" + records +
                '}';
    }
}
