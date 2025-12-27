package com.SwSOFTWARE.gatewayMs.security;


import com.SwSOFTWARE.gatewayMs.filter.JwtSecurityContextRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http,
                                                         JwtSecurityContextRepository jwtSecurityContextRepository) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .securityContextRepository(jwtSecurityContextRepository)
                .authorizeExchange(ex -> ex
                        .pathMatchers("/api/auth/login/**", "/api/auth/register/**").permitAll()
                        .anyExchange().authenticated()
                )
                .build();
    }


}