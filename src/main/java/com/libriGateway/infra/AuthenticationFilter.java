package com.libriGateway.infra;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Component
public class AuthenticationFilter implements GatewayFilter {

    private final RouterValidator routerValidator;
    private final JwtUtil jwtUtil;
    private final RestTemplate restTemplate;
    private final CircuitBreaker circuitBreaker;

    @Autowired
    public AuthenticationFilter(
            RouterValidator routerValidator,
            JwtUtil jwtUtil,
            CircuitBreakerRegistry circuitBreakerRegistry,
            @LoadBalanced RestTemplate restTemplate) { // Injeta o RestTemplate configurado

        this.routerValidator = routerValidator;
        this.jwtUtil = jwtUtil;
        this.restTemplate = restTemplate; // Usa o injetado
        this.circuitBreaker = circuitBreakerRegistry
                .circuitBreaker("userServiceTokenValidation");

        System.out.println("✅ AuthenticationFilter inicializado com RestTemplate com LoadBalancer");
    }


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();
        String method = request.getMethod().name();

        System.out.println("Request: " + method + " " + path);

        // Verifica se é uma rota pública
        if (!routerValidator.isSecured.test(request)) {
            System.out.println("Public route: " + path);
            return chain.filter(exchange);
        }

        // Para rotas protegidas, valida o token
        return validateTokenAndProceed(exchange, chain);
    }

    private Mono<Void> validateTokenAndProceed(ServerWebExchange exchange,
                                               GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        // Tenta obter o token do header primeiro
        List<String> authHeaders = request.getHeaders().get("Authorization");
        String token = null;

        if (authHeaders != null && !authHeaders.isEmpty()) {
            String authHeader = authHeaders.get(0);

            if (authHeader.startsWith("Bearer ")) {
                token = authHeader.substring(7).trim();
            } else {
                token = authHeader.trim(); // Se não começa com "Bearer ", assume que é token puro no header
            }
        }

        // Se não encontrou no header, tenta extrair do body (para POST/PUT)
        if (token == null && (HttpMethod.POST.equals(request.getMethod()) ||
                HttpMethod.PUT.equals(request.getMethod()))) {
            return extractTokenFromBody(exchange, chain);
        } else if (token == null) {
            System.out.println("Missing Authorization header or token");
            return onError(exchange, HttpStatus.UNAUTHORIZED, "Token não fornecido");
        }

        return validateTokenAndContinue(token, exchange, chain);
    }

    private Mono<Void> extractTokenFromBody(ServerWebExchange exchange,
                                            GatewayFilterChain chain) {
        // CachedBodyServerHttpRequestWrapper é necessário para ler o body múltiplas vezes
        return DataBufferUtils.join(exchange.getRequest().getBody())
                .flatMap(dataBuffer -> {
                    byte[] bytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bytes);
                    DataBufferUtils.release(dataBuffer);

                    String body = new String(bytes, StandardCharsets.UTF_8);

                    try {
                        // Tenta extrair token do JSON body
                        ObjectMapper mapper = new ObjectMapper();
                        JsonNode jsonNode = mapper.readTree(body);

                        String token = null;

                        // Procura por campos comuns que podem conter o token
                        if (jsonNode.has("token")) {
                            token = jsonNode.get("token").asText();
                        } else if (jsonNode.has("accessToken")) {
                            token = jsonNode.get("accessToken").asText();
                        } else if (jsonNode.has("authorization")) {
                            token = jsonNode.get("authorization").asText();
                        }

                        if (token != null && !token.isEmpty()) {
                            // Remove "Bearer " se presente
                            if (token.startsWith("Bearer ")) {
                                token = token.substring(7).trim();
                            }

                            // Valida o token
                            return validateTokenAndContinue(token, exchange, chain);
                        } else {
                            return onError(exchange, HttpStatus.UNAUTHORIZED,
                                    "Token não encontrado no corpo da requisição");
                        }
                    } catch (Exception e) {
                        return onError(exchange, HttpStatus.BAD_REQUEST,
                                "Erro ao processar corpo da requisição: " + e.getMessage());
                    }
                });
    }

    private Mono<Void> validateTokenAndContinue(String token,
                                                ServerWebExchange exchange,
                                                GatewayFilterChain chain) {
        // 1. Valida se token é válido (não expirado)
        if (jwtUtil.isInvalid(token)) {
            System.out.println("❌ Invalid token (expired or malformed)");
            return onError(exchange, HttpStatus.FORBIDDEN, "Token inválido ou expirado");
        }

        System.out.println("✅ Token JWT válido localmente");

        // 2. Verifica se token está na blacklist (logout)
        return checkTokenBlacklist(token).flatMap(shouldBlock -> {
            if (shouldBlock) {
                System.out.println("❌ Token bloqueado - Razão: " +
                        (shouldBlock ? "Blacklist ou serviço indisponível" : "Desconhecido"));
                return onError(exchange, HttpStatus.UNAUTHORIZED,
                        "Token invalidado ou serviço de autenticação indisponível");
            }

            System.out.println("✅ Token validado com sucesso (não está na blacklist)");
            System.out.println("Token: " + token);

            // Adiciona o token como header para o microservice downstream
            ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                    .header("Authorization", "Bearer " + token)
                    .build();

            return chain.filter(exchange.mutate().request(mutatedRequest).build());
        });
    }

    private Mono<Boolean> checkTokenBlacklist(String token) {
        return Mono.fromCallable(() -> {
            try {
                // Using Circuit Breaker
                Boolean result = circuitBreaker.executeSupplier(() -> {
                    // URL com service discovery (não precisa de IP)
                    String url = "http://user-service/auth/validate-token?token=" +
                            URLEncoder.encode(token, StandardCharsets.UTF_8);

                    System.out.println("🔍 Chamando user-service via LoadBalancer: " + url);

                    ResponseEntity<Boolean> response = restTemplate.getForEntity(
                            url, Boolean.class);

                    if (!response.getStatusCode().is2xxSuccessful()) {
                        throw new RuntimeException("Serviço retornou erro: " +
                                response.getStatusCode());
                    }

                    // IMPORTANTE: Invertemos a lógica aqui
                    // API retorna TRUE se token é válido, FALSE se está na blacklist
                    // Nós queremos retornar TRUE se deve BLOQUEAR
                    Boolean apiResponse = response.getBody();
                    System.out.println("✅ Resposta do user-service: " + apiResponse);
                    return Boolean.FALSE.equals(apiResponse); // TRUE = bloquear
                });

                return result;

            } catch (Exception e) {
                System.out.println("❌ Erro ao validar token no user-service: " + e.getClass().getSimpleName());
                System.out.println("Mensagem: " + e.getMessage());
                System.out.println("⚠️  Serviço de autenticação indisponível - BLOQUEANDO requisição");
                return true; // BLOQUEIA em caso de erro
            }
        }).subscribeOn(Schedulers.boundedElastic());
    }

    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus status, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().add("Content-Type", "application/json");

        String body = String.format(
                "{\"timestamp\": \"%s\", \"status\": %d, \"error\": \"%s\", \"message\": \"%s\"}",
                java.time.LocalDateTime.now(),
                status.value(),
                status.getReasonPhrase(),
                message
        );

        return response.writeWith(
                Mono.just(response.bufferFactory().wrap(body.getBytes()))
        );
    }
}