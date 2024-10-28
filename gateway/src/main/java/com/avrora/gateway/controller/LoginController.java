package com.avrora.gateway.controller;

import com.avrora.gateway.dto.LoginRequest;
import com.avrora.gateway.dto.LoginResponse;
import com.avrora.gateway.service.LoginService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    Logger log = LoggerFactory.getLogger(LoginController.class);


    @Autowired
    LoginService loginService;

    @PostMapping("login")
    public ResponseEntity<LoginResponse> login (@RequestBody LoginRequest loginRequest) throws Exception {
        log.info("Executing login");

        ResponseEntity<LoginResponse> response = null;
        response = loginService.login(loginRequest);

        return response;
    }

    @PostMapping("login1")
    public LoginResponse login1 (@RequestBody LoginRequest loginRequest) throws Exception {
        log.info("Executing login");

        ResponseEntity<LoginResponse> response = null;
        response = loginService.login(loginRequest);

        return response.getBody();
    }


}