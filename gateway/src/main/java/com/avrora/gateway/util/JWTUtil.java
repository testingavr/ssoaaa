package com.avrora.gateway.util;

import com.nimbusds.jose.shaded.gson.internal.LinkedTreeMap;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import org.springframework.http.server.reactive.ServerHttpRequest;


import java.text.ParseException;
import java.util.List;

public class JWTUtil {

    public static boolean hasRole(ServerHttpRequest request,String role)
    {

        String tokenString= request.getHeaders().getFirst("Authorization");

        try {
            if(tokenString == null || !tokenString.startsWith("Bearer "))
                return false;
            JWT jwt = JWTParser.parse(tokenString.substring(7));
           var rolesObj= jwt.getJWTClaimsSet().getClaim("realm_access");
           if(rolesObj instanceof LinkedTreeMap<?, ?> roles)
           {
               if(roles.get("roles") instanceof List<?> roleList)
               {
                   return roleList.contains(role);
               }
           }
            return false;
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }
}
