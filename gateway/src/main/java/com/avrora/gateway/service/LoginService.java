package com.avrora.gateway.service;

import com.avrora.gateway.dto.LoginRequest;
import com.avrora.gateway.dto.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

@Service
public class LoginService {

    @Value("${spring.security.oauth2.client.provider.keycloak.token-uri}")
    private String tokenUrl;
    @Value("${spring.security.oauth2.client.registration.spring-with-test-scope.client-secret}")
    private String clientSecret;
    @Value("${spring.security.oauth2.client.registration.spring-with-test-scope.authorization-grant-type}")
    private String grantType;
    @Value("${spring.security.oauth2.client.registration.spring-with-test-scope.client-id}")
    private String clientId;

    @Autowired
    RestTemplate restTemplate;

    public ResponseEntity<LoginResponse> login (LoginRequest request)  {

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("username", request.getUsername());
        map.add("password", request.getPassword());
        map.add("client_id", clientId);
      //  map.add("client_secret", clientSecret);
        map.add("grant_type", grantType);

        HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(map, headers);
        ResponseEntity<LoginResponse> loginResponse = restTemplate.postForEntity(tokenUrl, httpEntity, LoginResponse.class);

        return ResponseEntity.status(200).body(loginResponse.getBody());

    }
}