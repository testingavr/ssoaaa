package com.avrora.testapp;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import org.apache.tomcat.util.buf.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

@RestController
@RequestMapping("/caller")
public class CallerController {

    /*
    @Autowired
    private WebClient webClient;

    public CallerController(WebClient webClient) {
        this.webClient = webClient;
    }
*/
    @GetMapping("/ping")
    public String ping() {
        Logger logger = new LoggerContext().getLogger(CallerController.class);
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();

       /* String scopes = webClient
                .get()
                .uri("http://localhost:8040/callme/ping")
                .retrieve()
                .bodyToMono(String.class)
                .block();*/
        var arr =  authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority);
        var str = "Callme scopes: " + StringUtils.join(arr.toArray(String[]::new));
        logger.info("****** "+str+" *******");
        return str  ;
    }
}
