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

/**
 * Serviço central para geração e validação de tokens JWT.
 * 
 * <p>
 * <b>Funcionalidades:</b>
 * </p>
 * <ul>
 * <li>Gera tokens JWT assinados com RSA</li>
 * <li>Incorpora claims customizados (usuário, permissões, expiração)</li>
 * <li>Tratamento padronizado de erros</li>
 * </ul>
 *
 * <p>
 * <b>Pré-requisitos:</b>
 * </p>
 * <ul>
 * <li>Bean {@link JwtEncoder} configurado</li>
 * <li>Chaves RSA válidas (geradas ou fornecidas)</li>
 * </ul>
 */
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
	 * Gera um token JWT assinado após validar parâmetros essenciais.
	 * 
	 * <p>
	 * <b>Pré-condições:</b>
	 * </p>
	 * <ul>
	 * <li>{@code usuario} não pode ser {@code null}</li>
	 * <li>{@code usuario} deve conter a chave "usuario"</li>
	 * <li>{@code expiracao} deve ser maior que zero</li>
	 * </ul>
	 *
	 * <p>
	 * <b>Estrutura do token:</b>
	 * </p>
	 * <ul>
	 * <li>Issuer: {@code http://authtokenservice}</li>
	 * <li>Subject: Nome do usuário</li>
	 * <li>Claims customizados: permissões como {@code scope}</li>
	 * </ul>
	 *
	 * @param usuario   Mapa contendo:
	 *                  <ul>
	 *                  <li>{@code usuario} (obrigatório): Nome do usuário</li>
	 *                  <li>{@code permissoes} (opcional): String com permissões
	 *                  separadas por vírgula</li>
	 *                  </ul>
	 * @param expiracao Tempo de vida do token em segundos (deve ser positivo)
	 * @return {@link ResponseEntity} contendo:
	 *         <ul>
	 *         <li>200 com o token JWT no corpo em caso de sucesso</li>
	 *         <li>400 com mensagem específica em caso de:
	 *         <ul>
	 *         <li>Mapa de usuário nulo</li>
	 *         <li>Chave "usuario" ausente</li>
	 *         <li>Tempo de expiração inválido</li>
	 *         <li>Erro na geração do token</li>
	 *         </ul>
	 *         </li>
	 *         </ul>
	 * @throws IllegalArgumentException Se {@code expiracao} ≤ 0
	 * @throws NullPointerException     Se {@code usuario} for nulo ou sem chave
	 *                                  "usuario"
	 * 
	 * @example {@code
	 * // Uso válido
	 * Map<String, String> usuario = Map.of(
	 *     "usuario", "admin",
	 *     "permissoes", "ROLE_ADMIN,ROLE_USER"
	 * );
	 * ResponseEntity<?> resposta = tokenService.gerarToken(usuario, 3600);
	 * 
	 * // Exemplo de erro
	 * ResponseEntity<?> resposta = tokenService.gerarToken(null, 3600); 
	 * // Retorna: HTTP 400 - "Mapa de usuário não pode ser nulo"
	 * }
	 */
	public ResponseEntity<?> gerarToken(Map<String, String> usuario, long expiracao) {

		// Validações explícitas (Fail Fast)
		if (usuario == null) {

			return ResponseEntity.badRequest().body("Map de usuário não pode ser nulo");

		}

		if (!usuario.containsKey("usuario")) {

			return ResponseEntity.badRequest().body("Chave 'usuario' é obrigatória");

		}

		if (expiracao <= 0) {

			return ResponseEntity.badRequest().body("Expiração deve ser maior que zero");

		}

		try {

			final String username = usuario.get("usuario");
			final Instant agora = Instant.now();

			Builder claimsBuilder = JwtClaimsSet.builder().issuer("http://authtokenservice").subject(username)
					.issuedAt(agora).expiresAt(agora.plusSeconds(expiracao));

			if (usuario.containsKey("permissoes")) {

				claimsBuilder.claim("scope", usuario.get("permissoes").replaceAll("\\s+", ""));

			}

			Jwt token = jwtEncoder.encode(JwtEncoderParameters.from(claimsBuilder.build()));

			return ResponseEntity.ok(token);

		} catch (Exception e) {

			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Falha na geração do token: " + e.getMessage());

		}

	}

}