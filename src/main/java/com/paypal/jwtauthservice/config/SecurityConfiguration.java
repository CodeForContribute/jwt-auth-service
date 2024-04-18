package com.paypal.jwtauthservice.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(authorizeConfig->{
                    authorizeConfig.requestMatchers("/").permitAll();
                    authorizeConfig.requestMatchers("/login").permitAll();
                    authorizeConfig.requestMatchers("/logout").permitAll();
                    authorizeConfig.anyRequest().authenticated();

                })
                .sessionManagement(sessionManagementConfig->{
                    sessionManagementConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                })
                .build();
    }
}
