package com.auth.service;

import java.time.Instant;
import java.util.Date;
import java.util.Map;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

/**
 * Serviço responsável pela geração de tokens JWT assinados utilizando algoritmo
 * HMAC SHA-256.
 *
 * Esta classe é independente de framework web e pode ser utilizada em qualquer
 * aplicação Java.
 */
public class TokenService {

	private final Algorithm algorithm;

	/**
	 * Inicializa o serviço com chave simétrica em Base64.
	 *
	 * @param base64Secret chave secreta codificada em Base64
	 */
	public TokenService(String base64Secret) {
		byte[] keyBytes = java.util.Base64.getDecoder().decode(base64Secret);
		this.algorithm = Algorithm.HMAC256(keyBytes);
	}

	/**
	 * Gera um token JWT com base nos dados fornecidos.
	 *
	 * @param usuario           mapa contendo dados do usuário
	 * @param expiracaoSegundos tempo de expiração em segundos
	 * @return token JWT assinado
	 * @throws IllegalArgumentException se os parâmetros forem inválidos
	 */
	public String gerarToken(Map<String, String> usuario, long expiracaoSegundos) {

		if (usuario == null) {

			throw new IllegalArgumentException("Map de usuário não pode ser nulo");

		}

		if (!usuario.containsKey("usuario")) {

			throw new IllegalArgumentException("Chave 'usuario' é obrigatória");

		}

		if (expiracaoSegundos <= 0) {

			throw new IllegalArgumentException("Expiração deve ser maior que zero");

		}

		final Instant agora = Instant.now();
		final Date issuedAt = Date.from(agora);
		final Date expiresAt = Date.from(agora.plusSeconds(expiracaoSegundos));

		var builder = JWT.create().withIssuer("http://authtokenservice").withSubject(usuario.get("usuario"))
				.withIssuedAt(issuedAt).withExpiresAt(expiresAt);

		// Claim opcional de permissões
		if (usuario.containsKey("permissoes")) {

			builder.withClaim("scope", usuario.get("permissoes").replaceAll("\\s+", ""));

		}

		return builder.sign(algorithm);
	}

}