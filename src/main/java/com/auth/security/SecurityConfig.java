package com.auth.security;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.auth.service.TokenService;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;

/**
 * Configuração automática de segurança para aplicações Spring Boot.
 * 
 * <p>Fornece:</p>
 * <ul>
 *   <li>Configuração JWT com chaves RSA</li>
 *   <li>Proteção de rotas com OAuth2 Resource Server</li>
 *   <li>Injeção automática do TokenService</li>
 * </ul>
 * 
 * <p><b>Pré-requisitos:</b></p>
 * <ul>
 *   <li>Properties <code>jwt.public.key</code> e <code>jwt.private.key</code> configuradas</li>
 *   <li>Bean <code>List<RequestMatcher> rotasPublicas</code> definido no projeto consumidor</li>
 * </ul>
 */
@Configuration
@AutoConfiguration // Habilita auto-configuração Spring Boot 3+
@EnableWebSecurity
public class SecurityConfig {

    @Value("${jwt.public.key}")
    private RSAPublicKey chavePublica;

    @Value("${jwt.private.key}")
    private RSAPrivateKey chavePrivada;

    /**
     * Configura o decodificador JWT com a chave pública RSA.
     */
    @Bean
    JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(chavePublica).build();
    }

    /**
     * Fornece uma implementação padrão do TokenService caso nenhuma seja definida.
     */
    @Bean
    @ConditionalOnMissingBean
    TokenService tokenService(JwtEncoder jwtEncoder) {
        return new TokenService(jwtEncoder);
    }

    /**
     * Configura o codificador JWT com par de chaves RSA.
     */
    @Bean
    JwtEncoder jwtEncoder() {
        JWK jwk = new RSAKey.Builder(this.chavePublica)
            .privateKey(chavePrivada)
            .build();
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(jwk)));
    }

    /**
     * Configura a cadeia de filtros de segurança.
     * 
     * @param rotasPublicas Deve ser fornecido pelo projeto consumidor via @Bean
     */
    @Bean
    SecurityFilterChain securityFilterChain(
        HttpSecurity http, 
        @Qualifier("rotasPublicas") List<RequestMatcher> rotasPublicas
    ) throws Exception {
        http
            .csrf(Customizer.withDefaults())
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