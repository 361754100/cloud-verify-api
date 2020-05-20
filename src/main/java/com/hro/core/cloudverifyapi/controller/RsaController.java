package com.hro.core.cloudverifyapi.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RsaController {

    private static Logger logger = LoggerFactory.getLogger(RsaController.class);


    @GetMapping("/rsa/test")
    public boolean test() {
//        // 故意延迟测试hystrixcommand
        try {
            Thread.sleep(2*1000l);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        logger.debug("rsa test...");
        return true;
    }
}