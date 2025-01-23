package com.basic.securityDemo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class entryController {

    @GetMapping("/hi")
    public String Greetings(){
        return "Hello";
    }
}
