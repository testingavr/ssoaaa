package com.avrora.gateway.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
public class OAuth2ResourceServerController {
/*
    @Autowired
    private ReactiveOAuth2AuthorizedClientManager authorizedClientManager;

    @PostMapping("/resource")
    public Mono<OAuth2AccessToken> resource(JwtAuthenticationToken jwtAuthentication) {
        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId("okta")
                .principal(jwtAuthentication)
                .build();

        return this.authorizedClientManager.authorize(authorizeRequest)
                .map(OAuth2AuthorizedClient::getAccessToken);
    }
*/

}