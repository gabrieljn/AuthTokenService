# 🔐 AuthTokenService

Fornece uma configuração automática de segurança baseada em **JWT com chaves RSA** para aplicações Spring Boot 3+.  
Ela oferece geração e validação de tokens seguros, com autenticação stateless, e permite fácil customização de rotas públicas.

**Versão funcional: 1.6**

## ✨ Funcionalidades

✅ Autoconfiguração de segurança com Spring Security  
🔐 Geração de tokens JWT assinados com chave privada RSA  
🔍 Validação de tokens JWT com chave pública RSA  
🛡️ Proteção de rotas com OAuth2 Resource Server  
🧩 Suporte a claims personalizados (usuário, permissões, expiração)  
♻️ Stateless: sem uso de sessões ou cookies  
⚙️ Possibilidade de sobrescrever o `TokenService` padrão  

## 🧾 Pré-requisitos

- Java 17+  
- Spring Boot 3.0+  
- Par de chaves RSA (pública e privada)  

## 📦 Instalação via Maven

Adicione a seguinte dependência no seu `pom.xml`:

```xml
<dependency>
    <groupId>io.github.gabrieljn</groupId>
    <artifactId>AuthTokenService</artifactId>
    <version>1.6</version>
</dependency>
```

## ⚙️ Configuração

### 1. Propriedades obrigatórias

Adicione as chaves RSA ao seu `application.properties`:

```properties
# application.properties
jwt.public.key=<sua-chave-publica-em-PEM-ou-Java-encoded>
jwt.private.key=<sua-chave-privada-em-PEM-ou-Java-encoded>
```

### 2. Definir rotas públicas

No projeto que consome a lib, você deve registrar um bean com as rotas públicas da aplicação:

```java
@Bean
public List<RequestMatcher> rotasPublicas() {
    return List.of(
        new AntPathRequestMatcher("/login"),
        new AntPathRequestMatcher("/public/**")
    );
}
```

## 📤 Uso do TokenService

### Geração de Token

O `TokenService` já vem injetado automaticamente. Para gerar um token:

```java
Map<String, String> usuario = Map.of(
    "usuario", "admin",
    "permissoes", "ROLE_ADMIN,ROLE_USER"
);

ResponseEntity<?> resposta = tokenService.gerarToken(usuario, 3600);
```

## 🛡️ Segurança

- ❌ CSRF desabilitado (por padrão)  
- ✅ Permissão automática para requisições `OPTIONS` (suporte a CORS)  
- 🔐 Qualquer rota não listada nas `rotasPublicas` exige autenticação  

## 🛠️ Exemplo de Integração

```java
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final TokenService tokenService;

    public AuthController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> user) {
        return tokenService.gerarToken(user, 3600);
    }
}
```

## 📦 Estrutura dos Beans

| Bean                  | Tipo      | Finalidade                            |
|-----------------------|-----------|---------------------------------------|
| `TokenService`        | Singleton | Geração de tokens JWT                 |
| `JwtEncoder`          | Singleton | Codificador JWT com chave RSA         |
| `JwtDecoder`          | Singleton | Validador JWT com chave pública       |
| `SecurityFilterChain` | Singleton | Filtro de segurança (rotas, JWT, etc) |
