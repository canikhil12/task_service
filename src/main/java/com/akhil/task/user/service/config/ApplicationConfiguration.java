package com.akhil.task.user.service.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

@Configuration
public class ApplicationConfiguration {
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.sessionManagement(
                management->management.sessionCreationPolicy(
                        SessionCreationPolicy.STATELESS
                )
        ).authorizeHttpRequests(
                Authorize->Authorize.requestMatchers("/api/**").authenticated().anyRequest().permitAll()
        ).addFilterBefore(new JwtTokenValidator(), BasicAuthenticationFilter.class
        ).csrf(csrf->
            csrf.disable())
                    .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                    .httpBasic(Customizer.withDefaults())
                    .formLogin(Customizer.withDefaults());

            return http.build();
    }
    private CorsConfigurationSource corsConfigurationSource() {
    return new CorsConfigurationSource() {
        @Override
        public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
          CorsConfiguration chg=new CorsConfiguration();
          chg.setAllowedMethods(Collections.singletonList("*"));
          chg.setAllowedOrigins(Collections.singletonList("*"));
          chg.setAllowCredentials(true);
          chg.setAllowedHeaders(Collections.singletonList("*"));
          chg.setExposedHeaders(Arrays.asList("Authorization"));
          chg.setMaxAge(3600L);
          return chg;
        }
        };
    }
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
    }
}