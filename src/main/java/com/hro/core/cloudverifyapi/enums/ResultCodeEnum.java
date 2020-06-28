package com.hro.core.cloudverifyapi.enums;

import java.util.Arrays;
import java.util.List;

/**
 * 结果集状态码
 */
public enum ResultCodeEnum {

    UNKNOW("-1", "未知异常"),
    FORBIDDEN("403", "没有权限访问"),
    RESOURCE_NOT_FOUND("404", "资源不存在"),
    SESSION_TIMEOUT("405", "用户会话超时"),
    SUCCESS("100", "成功"),
    PARAM_ERROR("104", "参数错误"),
    TOKEN_UNVALIDATE("204", "token无效"),
    TOKEN_TIMEOUT("205", "token超时"),
    FAILURE("999", "系统错误");

    private String code;
    private String desc;
    private static ResultCodeEnum[] values = values();

    ResultCodeEnum(String code, String desc) {
        this.code = code;
        this.desc = desc;
    }

    public String getCode() {
        return this.code;
    }

    public String getDesc() {
        return this.desc;
    }

    public static ResultCodeEnum getResult(String code) {
        ResultCodeEnum result = UNKNOW;
        for(ResultCodeEnum codeEnum : values) {
            if(code.equals(codeEnum.getCode())) {
                result = codeEnum;
                break;
            }
        }
        return result;
    }

    public static List<ResultCodeEnum> getResultCodes() {
        ResultCodeEnum[] enums = values();
        List<ResultCodeEnum> list = Arrays.asList(enums);
        return list;
    }

}
