package com.hro.core.cloudverifyapi.response;


import com.hro.core.cloudverifyapi.enums.ResultCodeEnum;

import java.io.Serializable;

/**
 * Http 响应消息体父类
 */
public class CommonWrapper implements Serializable{
    /**
     * 状态码
     */
    public String code = ResultCodeEnum.SUCCESS.getCode();

    /**
     * 处理结果
     */
    public String msg = ResultCodeEnum.SUCCESS.getDesc();

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String resultMsg) {
        this.msg = resultMsg;
    }
}
