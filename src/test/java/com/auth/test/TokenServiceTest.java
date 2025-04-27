package com.auth.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;

import com.auth.service.TokenService;

/**
 * Testes unitários para o serviço TokenService.
 * 
 * Testa a geração de tokens JWT e o comportamento do serviço em diferentes cenários.
 */
class TokenServiceTest {

    private TokenService tokenService;
    private JwtEncoder jwtEncoder;

    /**
     * Inicializa os mocks antes de cada teste.
     */
    @BeforeEach
    void setUp() {
        // Criando um mock para o JwtEncoder
        jwtEncoder = mock(JwtEncoder.class);
        tokenService = new TokenService(jwtEncoder); // Injetando o mock no serviço
    }

    /**
     * Testa a geração de um token JWT com permissões válidas.
     */
    @Test
    void testGerarToken() {
        Jwt mockJwt = mock(Jwt.class);
        when(jwtEncoder.encode(any())).thenReturn(mockJwt);

        // Dados de entrada para o usuário
        Map<String, String> usuario = Map.of("usuario", "testUser", "permissoes", "read write");

        // Gerar o token através do serviço
        ResponseEntity<?> response = tokenService.gerarToken(usuario, 3600);

        // Verificação se o código de status é 200 (OK) e se o corpo contém o token gerado
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody() instanceof Jwt);
    }

    /**
     * Testa a geração de um token JWT sem permissões.
     */
    @Test
    void testGerarTokenSemPermissoes() {
        Jwt mockJwt = mock(Jwt.class);
        when(jwtEncoder.encode(any())).thenReturn(mockJwt);

        // Dados de entrada para o usuário sem permissões
        Map<String, String> usuario = Map.of("usuario", "testUser");

        // Gerar o token através do serviço
        ResponseEntity<?> response = tokenService.gerarToken(usuario, 3600);

        // Verificação se o código de status é 200 (OK) e se o corpo contém o token gerado
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody() instanceof Jwt);
    }

    /**
     * Testa o comportamento do serviço ao gerar um token com erro.
     */
    @Test
    void testGerarTokenComErro() {
        when(jwtEncoder.encode(any())).thenThrow(new RuntimeException("Erro ao gerar token"));

        Map<String, String> usuario = Map.of("usuario", "testUser");

        // Espera-se um erro 400 com a mensagem "Erro:"
        ResponseEntity<?> response = tokenService.gerarToken(usuario, 3600);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertTrue(response.getBody().toString().contains("Erro:"));
    }
}
