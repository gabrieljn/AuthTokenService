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
 *   <li>Bean <code>List&lt;RequestMatcher&gt; rotasPublicas</code> definido no projeto consumidor</li>
 * </ul>
 * 
 * <p><b>Observação:</b> Como esta lib utiliza autenticação via JWT (stateless), a proteção CSRF é desabilitada por padrão.</p>
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
     * Configura o decodificador JWT usando a chave pública RSA fornecida via application.properties.
     * 
     * @return uma instância de JwtDecoder para validar tokens JWT.
     */
    @Bean
    JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(chavePublica).build();
    }

    /**
     * Cria uma instância padrão de TokenService caso o projeto consumidor não forneça uma.
     * 
     * @param jwtEncoder Encoder JWT configurado com chave RSA.
     * @return uma instância de TokenService para geração de tokens.
     */
    @Bean
    @ConditionalOnMissingBean
    TokenService tokenService(JwtEncoder jwtEncoder) {
        return new TokenService(jwtEncoder);
    }

    /**
     * Configura o codificador JWT utilizando as chaves RSA públicas e privadas.
     * 
     * @return uma instância de JwtEncoder para emitir tokens JWT assinados.
     */
    @Bean
    JwtEncoder jwtEncoder() {
        JWK jwk = new RSAKey.Builder(chavePublica)
            .privateKey(chavePrivada)
            .build();
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(jwk)));
    }

    /**
     * Configura a cadeia de filtros de segurança do Spring Security.
     * 
     * <p>Essa configuração desabilita CSRF, define a política de sessão como stateless
     * e protege as rotas usando OAuth2 Resource Server com JWT.</p>
     * 
     * @param http objeto HttpSecurity fornecido pelo Spring
     * @param rotasPublicas lista de rotas públicas a serem liberadas (fornecida pelo projeto consumidor via @Bean)
     * @return SecurityFilterChain configurada
     * @throws Exception caso ocorra erro na configuração
     */
    @Bean
    SecurityFilterChain securityFilterChain(
        HttpSecurity http,
        @Qualifier("rotasPublicas") List<RequestMatcher> rotasPublicas
    ) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // Desabilita CSRF porque usa JWT
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Stateless, sem sessão
            .authorizeHttpRequests(auth -> {
                auth.requestMatchers(HttpMethod.OPTIONS).permitAll(); // Permite OPTIONS para CORS
                rotasPublicas.forEach(matcher -> auth.requestMatchers(matcher).permitAll()); // Permite rotas públicas definidas
                auth.anyRequest().authenticated(); // Protege todas as outras rotas
            })
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults())); // Configura autenticação JWT

        return http.build();
    }
}
