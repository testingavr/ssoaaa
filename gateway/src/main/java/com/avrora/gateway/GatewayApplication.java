package com.avrora.gateway;

import com.avrora.gateway.dto.LoginRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import reactor.core.publisher.Mono;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.server.WebSession;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;

@EnableDiscoveryClient
@SpringBootApplication
@RestController
public class GatewayApplication {

/*    @Autowired
    ReactiveOAuth2AuthorizedClientManager authorizedClientManager;
*/
    private static final Logger LOGGER = LoggerFactory.getLogger(GatewayApplication.class);

    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }

    @GetMapping(value = "/token")
    public Mono<String> getHome(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient) {
        return Mono.just(authorizedClient.getAccessToken().getTokenValue());
    }

    @GetMapping(value = "/refreshtoken")
    public Mono<String> getRefreshToken(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient) {
        return Mono.just(authorizedClient.getRefreshToken().getTokenValue());
    }

    @GetMapping("/")
    public Mono<String> index(WebSession session) {
        return Mono.just(session.getId());
    }

    @PostMapping("logout")
    public String logout()
    {
        return  "";
    }
/*
    @PostMapping("/loginapi")
    public String index(@RequestBody LoginRequest loginRequest) throws ExecutionException, InterruptedException {
        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId("spring-with-test-scope")
                .principal(loginRequest.getUsername())
                .attribute(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, loginRequest.getPassword())
         .build();
        Mono<OAuth2AuthorizedClient> authorizedClient = this.authorizedClientManager.authorize(authorizeRequest);

var token =authorizedClient.block();
if(token != null) {
    return  token.getAccessToken().getTokenValue();

}
return null;

     //   return accessToken.getTokenValue();
    }
*/
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

}