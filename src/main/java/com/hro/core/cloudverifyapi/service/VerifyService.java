package com.hro.core.cloudverifyapi.service;

import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class VerifyService {

    private static Logger logger = LoggerFactory.getLogger(VerifyService.class);


    public boolean rsaTokenCheck(String token) {
        boolean isOk = false;

        return isOk;
    }
}
