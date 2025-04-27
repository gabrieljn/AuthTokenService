package com.auth.service;

import java.time.Instant;
import java.util.Map;

import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtClaimsSet.Builder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

/**
 * Serviço central para geração e validação de tokens JWT.
 * 
 * <p><b>Funcionalidades:</b></p>
 * <ul>
 *   <li>Gera tokens JWT assinados com RSA</li>
 *   <li>Incorpora claims customizados (usuário, permissões, expiração)</li>
 *   <li>Tratamento padronizado de erros</li>
 * </ul>
 *
 * <p><b>Pré-requisitos:</b></p>
 * <ul>
 *   <li>Bean {@link JwtEncoder} configurado</li>
 *   <li>Chaves RSA válidas (geradas ou fornecidas)</li>
 * </ul>
 */
@Service
@Primary
public class TokenService {

    private final JwtEncoder jwtEncoder;

    /**
     * Construtor para injeção de dependências.
     * 
     * @param jwtEncoder Codificador JWT configurado com as chaves RSA
     */
    public TokenService(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    /**
     * Gera um token JWT assinado.
     * 
     * <p><b>Estrutura do token:</b></p>
     * <ul>
     *   <li>Issuer: {@code http://authtokenservice}</li>
     *   <li>Subject: Nome do usuário</li>
     *   <li>Claims customizados: permissões como {@code scope}</li>
     * </ul>
     *
     * @param usuario Mapa contendo:
     *                <ul>
     *                  <li>{@code usuario}: Nome do usuário (obrigatório)</li>
     *                  <li>{@code permissoes}: String com permissões separadas por vírgula (opcional)</li>
     *                </ul>
     * @param expiracao Tempo de vida do token em segundos
     * @return {@link ResponseEntity} contendo:
     *         <ul>
     *           <li>200 com o token JWT no corpo em caso de sucesso</li>
     *           <li>400 com mensagem de erro em caso de falha</li>
     *         </ul>
     * @throws IllegalArgumentException Se parâmetros essenciais forem nulos/vazios
     * 
     * @example {@code
     * Map<String, String> usuario = Map.of(
     *     "usuario", "admin",
     *     "permissoes", "ROLE_ADMIN,ROLE_USER"
     * );
     * ResponseEntity<?> resposta = tokenService.gerarToken(usuario, 3600);
     * }
     */
    public ResponseEntity<?> gerarToken(Map<String, String> usuario, long expiracao) {
        try {
            // Validação implícita via NPE
            final String username = usuario.get("usuario");
            final Instant agora = Instant.now();

            Builder claimsBuilder = JwtClaimsSet.builder()
                .issuer("http://authtokenservice")
                .subject(username)
                .issuedAt(agora)
                .expiresAt(agora.plusSeconds(expiracao));

            if (usuario.containsKey("permissoes")) {
                claimsBuilder.claim("scope", 
                    usuario.get("permissoes").replaceAll("\\s+", ""));
            }

            Jwt token = jwtEncoder.encode(
                JwtEncoderParameters.from(claimsBuilder.build())
            );

            return ResponseEntity.ok(token);

        } catch (Exception e) {
            return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body("Falha na geração do token: " + e.getMessage());
        }
    }
}