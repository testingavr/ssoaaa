package com.avrora.gateway.config;

import com.avrora.gateway.util.JWTUtil;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class RoleAuthGatewayFilterFactory extends
        AbstractGatewayFilterFactory<RoleAuthGatewayFilterFactory.Config> {

    public RoleAuthGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            var request = exchange.getRequest();
            // JWTUtil can extract the token from the request, parse it and verify if the given role is available
            if(!JWTUtil.hasRole(request, config.getRole())){
                // seems we miss the auth token
                var response = exchange.getResponse();
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                return response.setComplete();
            }
            return chain.filter(exchange);
        };
    }

    public static class Config {
        private String role;

        public String getRole() {
            return role;
        }
        public void setRole(String role) {this.role = role;}
    }

    @Override
    public List<String> shortcutFieldOrder() {
        // we need this to use shortcuts in the application.yml
        return List.of("role");
    }
}