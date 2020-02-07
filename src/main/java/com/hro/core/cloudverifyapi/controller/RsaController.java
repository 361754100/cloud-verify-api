package com.hro.core.cloudverifyapi.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RsaController {

    @GetMapping("/test")
    public boolean test() {
        return false;
    }
}
