package com.auth.service;

import java.time.Instant;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtClaimsSet.Builder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

@Service
public class TokenService {

	private JwtEncoder jwtEncoder;

	public TokenService(JwtEncoder jwtEncoder) {
		super();
		this.jwtEncoder = jwtEncoder;
	}

	public ResponseEntity<?> gerarToken(Map<String, String> usuario, long expiracao) {
		try {
		
			Instant agora = Instant.now();

	        Builder claimsBuilder = JwtClaimsSet.builder()
	                .issuer("http://authtokenservice")
	                .subject(usuario.get("usuario"))
	                .issuedAt(agora)
	                .expiresAt(agora.plusSeconds(expiracao));
			
	        if (usuario.containsKey("permissoes")) {
	            String permissoes = usuario.get("permissoes");
	            String scopes = permissoes.replaceAll("\\s+", "");
	            claimsBuilder.claim("scope", scopes); 
	        }
	        
	        JwtClaimsSet claims = claimsBuilder.build();

			Jwt jwtValue = jwtEncoder.encode(JwtEncoderParameters.from(claims));

	        return ResponseEntity.ok(jwtValue);

		} catch (Exception e) {
			 return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Erro: " + e.getMessage());
		}
	}
}