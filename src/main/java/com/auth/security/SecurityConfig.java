package com.auth.security;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
import org.springframework.stereotype.Component;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;

/**
 * Configuração de segurança da aplicação, incluindo a configuração de JWT para
 * autenticação e autorização de usuários.
 * 
 * Configura o filtro de segurança da aplicação, os decodificadores e
 * codificadores de JWT e as rotas públicas e privadas.
 */
@Configuration
@EnableWebSecurity
@Component
public class SecurityConfig {

	@Value("${jwt.public.key}")
	private RSAPublicKey chavePublica;

	@Value("${jwt.private.key}")
	private RSAPrivateKey chavePrivada;

	/**
	 * Cria um bean JwtDecoder para decodificar tokens JWT usando a chave pública.
	 * 
	 * @return O JwtDecoder configurado para usar a chave pública.
	 */
	@Bean
	JwtDecoder jwtDecoder() {
		return NimbusJwtDecoder.withPublicKey(chavePublica).build();
	}

	/**
	 * Cria um bean JwtEncoder para codificar tokens JWT usando a chave privada e
	 * pública.
	 * 
	 * @return O JwtEncoder configurado para usar as chaves RSA.
	 */
	@Bean
	JwtEncoder jwtEncoder() {
		JWK jwk = new RSAKey.Builder(this.chavePublica).privateKey(chavePrivada).build();
		var jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
		return new NimbusJwtEncoder(jwks);
	}

	/**
	 * Configura as rotas públicas e privadas da aplicação, além da autenticação
	 * baseada em JWT.
	 * 
	 * @param http          O objeto HttpSecurity para configurar as regras de
	 *                      segurança.
	 * @param rotasPublicas A lista de rotas públicas que não necessitam de
	 *                      autenticação.
	 * @return O SecurityFilterChain configurado.
	 * @throws Exception Caso ocorra algum erro durante a configuração.
	 */
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http,
			@Qualifier("rotasPublicas") List<RequestMatcher> rotasPublicas) throws Exception {
		http.csrf(csrf -> csrf.disable())
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults())).authorizeHttpRequests(auth -> {

					rotasPublicas.forEach(matcher -> auth.requestMatchers(matcher).permitAll());
					auth.anyRequest().authenticated();

				});

		return http.build();
	}

}