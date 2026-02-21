package com.auth.security;

import java.util.Base64;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

import com.auth.service.TokenService;

@Configuration
public class SecurityConfig {

    @Value("${jwt.secret}")
    private String secret;

    /**
     * Disponibiliza o serviço responsável pela geração e validação de tokens JWT.
     */
    @Bean
    TokenService tokenService() {
        return new TokenService(secret);
    }

    /**
     * Configura o JwtDecoder utilizando chave simétrica (HMAC SHA-256).
     * A chave é lida do application.properties e decodificada em Base64.
     */
    @Bean
    JwtDecoder jwtDecoder() {
        byte[] keyBytes = Base64.getDecoder().decode(secret);
        SecretKey key = new SecretKeySpec(keyBytes, "HmacSHA256");
        return NimbusJwtDecoder.withSecretKey(key).build();
    }

    /**	
     * Configuração principal da cadeia de filtros de segurança.
     *
     * - Desabilita CSRF por se tratar de API stateless com autenticação via JWT.
     * - Define política de sessão como STATELESS.
     * - Permite requisições OPTIONS (necessárias para CORS).
     * - Libera acesso às rotas públicas configuradas.
     * - Exige autenticação para todas as demais requisições.
     * - Configura a aplicação como Resource Server com suporte a JWT.
     */
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, List<String> rotasPublicas) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) 
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> {
                auth.requestMatchers(HttpMethod.OPTIONS).permitAll();
                rotasPublicas.forEach(matcher -> auth.requestMatchers(matcher).permitAll());
                auth.anyRequest().authenticated();
            })
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

        return http.build();
    }
}