🔐 AuthTokenService

Biblioteca de segurança para Spring Boot 3+ com autenticação baseada em JWT assinado com HMAC SHA-256 (HS256).

Fornece geração e validação de tokens utilizando chave simétrica, com autenticação stateless e integração automática com Spring Security.

Versão atual: 1.7

✨ Funcionalidades

✅ Autoconfiguração de segurança com Spring Security
🔐 Geração de JWT assinado com HMAC SHA-256 (HS256)
🔍 Validação automática de token com chave simétrica
🛡️ Integração com OAuth2 Resource Server
🧩 Suporte a claims personalizadas (sub, scope, exp, etc.)
♻️ Stateless (sem sessão ou cookies)
⚙️ Permite sobrescrever o TokenService padrão

🧾 Pré-requisitos

Java 17+

Spring Boot 3+

Chave secreta codificada em Base64

📦 Instalação (Maven)
<dependency>
    <groupId>io.github.gabrieljn</groupId>
    <artifactId>AuthTokenService</artifactId>
    <version>1.7</version>
</dependency>
⚙️ Configuração
1️⃣ Definir chave secreta

No application.properties:

jwt.secret=<sua-chave-base64>

A chave deve estar codificada em Base64 e será utilizada tanto para assinatura quanto para validação do token.

2️⃣ Definir rotas públicas

No projeto que consome a lib:

@Bean
public List<String> rotasPublicas() {
    return List.of(
        "/login",
        "/public/**"
    );
}

Todas as demais rotas exigirão autenticação JWT automaticamente.

📤 Uso do TokenService

O TokenService é disponibilizado automaticamente como Bean.

✅ Gerar token
Map<String, String> usuario = Map.of(
    "usuario", "admin",
    "permissoes", "ROLE_ADMIN,ROLE_USER"
);

String token = tokenService.gerarToken(usuario, 3600);
Claims geradas
Claim	Descrição
iss	Issuer fixo da aplicação
sub	Valor da chave "usuario"
iat	Data de emissão
exp	Data de expiração
scope	Permissões (opcional)
🛡️ Segurança Aplicada

❌ CSRF desabilitado (API stateless)

✅ SessionCreationPolicy.STATELESS

✅ Permissão automática para requisições OPTIONS

🔐 Todas as rotas não públicas exigem JWT válido

🔑 Assinatura e validação usando mesma chave secreta (HS256)

🛠️ Exemplo de Integração REST
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final TokenService tokenService;

    public AuthController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> user) {

        String token = tokenService.gerarToken(user, 3600);

        return ResponseEntity.ok(Map.of("token", token));
    }
}
📦 Beans Registrados
Bean	Finalidade
TokenService	Geração de tokens JWT
JwtDecoder	Validação de tokens HS256
SecurityFilterChain	Configuração de segurança
