package com.avrora.gateway.controller;

import com.avrora.gateway.dto.LoginRequest;
import com.avrora.gateway.dto.LoginResponse;
import com.avrora.gateway.service.LoginService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping(value="/api")
public class LoginController {

    Logger log = LoggerFactory.getLogger(LoginController.class);


    @Autowired
    LoginService loginService;

    @PostMapping("login")
    public Mono<ResponseEntity<LoginResponse>> login (@RequestBody LoginRequest loginRequest) throws Exception {
        log.info("Executing login");

        ResponseEntity<LoginResponse> response = null;
        response = loginService.login(loginRequest);

        return Mono.just(response);
    }

}