package com.hro.core.cloudverifyapi.jwt;

public class JwtResult {

    private boolean status;
    private String uid;
    private String msg;
    private String code;

    public JwtResult() {
        super();
    }

    public JwtResult(boolean status, String uid, String msg, String code) {
        super();
        this.status = status;
        this.uid = uid;
        this.msg = msg;
        this.code = code;
    }

    public boolean isStatus() {
        return status;
    }

    public void setStatus(boolean status) {
        this.status = status;
    }

    public String getUid() {
        return uid;
    }

    public void setUid(String uid) {
        this.uid = uid;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }
}
