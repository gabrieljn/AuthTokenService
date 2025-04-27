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

/**
 * Serviço responsável pela geração de tokens JWT para autenticação.
 * 
 * Este serviço usa um JwtEncoder para gerar tokens com informações como
 * o usuário, permissões, data de expiração, etc.
 */
@Service
public class TokenService {

    private JwtEncoder jwtEncoder;

    /**
     * Construtor que recebe um JwtEncoder para gerar tokens JWT.
     * 
     * @param jwtEncoder O JwtEncoder usado para gerar os tokens.
     */
    public TokenService(JwtEncoder jwtEncoder) {
        super();
        this.jwtEncoder = jwtEncoder;
    }

    /**
     * Gera um token JWT para um usuário com permissões e um tempo de expiração.
     * 
     * @param usuario Dados do usuário, incluindo nome e permissões.
     * @param expiracao O tempo de expiração do token em segundos.
     * @return A resposta HTTP com o token gerado ou um erro se falhar.
     */
    public ResponseEntity<?> gerarToken(Map<String, String> usuario, long expiracao) {
        try {
            Instant agora = Instant.now();

            // Construção do conjunto de claims do JWT
            Builder claimsBuilder = JwtClaimsSet.builder()
                .issuer("http://authtokenservice")
                .subject(usuario.get("usuario"))
                .issuedAt(agora)
                .expiresAt(agora.plusSeconds(expiracao));

            // Adicionando permissões como escopos no token, se fornecido
            if (usuario.containsKey("permissoes")) {
                String permissoes = usuario.get("permissoes");
                String scopes = permissoes.replaceAll("\\s+", "");
                claimsBuilder.claim("scope", scopes);
            }

            // Gerando o token com os claims configurados
            JwtClaimsSet claims = claimsBuilder.build();
            Jwt jwtValue = jwtEncoder.encode(JwtEncoderParameters.from(claims));

            return ResponseEntity.ok(jwtValue);

        } catch (Exception e) {
            // Em caso de erro, retorna um erro 400 com a mensagem
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Erro: " + e.getMessage());
        }
    }
}