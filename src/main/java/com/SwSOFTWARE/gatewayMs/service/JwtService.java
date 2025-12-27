package com.SwSOFTWARE.gatewayMs.service;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;


import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Collections;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private  String secret;

    public Mono<UserDetails> validateToken(String token) {
        return Mono.fromCallable(() -> {
            System.out.println("12121212");

            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getKeu())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            System.out.println("66666");

            String username = claims.getSubject();
            if (username == null || username.isEmpty()) {
                throw new RuntimeException("Token inválido");
            }
                System.out.println("Dssdasdasdadsd");
            return User.withUsername(username)
                    .password("")
                    .authorities(Collections.emptyList())
                    .build();
        }).onErrorResume(e -> Mono.empty());
    }

    public Key getKeu(){
        byte[] key = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(key);
    }
}
