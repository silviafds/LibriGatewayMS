package com.libriGateway.infra;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.core5.util.Timeout;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
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

    @Autowired
    public AuthenticationFilter(RouterValidator routerValidator, JwtUtil jwtUtil) {
        this.routerValidator = routerValidator;
        this.jwtUtil = jwtUtil;
        this.restTemplate = createRestTemplate();
    }

    private RestTemplate createRestTemplate() {
        // Configuração do PoolingHttpClientConnectionManager
        PoolingHttpClientConnectionManager connectionManager =
                new PoolingHttpClientConnectionManager();
        connectionManager.setMaxTotal(100);
        connectionManager.setDefaultMaxPerRoute(20);

        // Configuração de timeout
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(Timeout.ofSeconds(3))
                .setResponseTimeout(Timeout.ofSeconds(3))
                .setConnectionRequestTimeout(Timeout.ofSeconds(3))
                .build();

        // Cria HttpClient
        CloseableHttpClient httpClient = HttpClients.custom()
                .setConnectionManager(connectionManager)
                .setDefaultRequestConfig(requestConfig)
                .build();

        // Cria RestTemplate
        HttpComponentsClientHttpRequestFactory factory =
                new HttpComponentsClientHttpRequestFactory(httpClient);

        return new RestTemplate(factory);
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
            System.out.println("Invalid token (expired or malformed)");
            return onError(exchange, HttpStatus.FORBIDDEN, "Token inválido ou expirado");
        }

        // 2. Verifica se token está na blacklist (logout)
        return checkTokenBlacklist(token).flatMap(isBlacklisted -> {
            if (isBlacklisted) {
                System.out.println("Token is blacklisted (user logged out)");
                return onError(exchange, HttpStatus.UNAUTHORIZED, "Token invalidado via logout");
            }

            System.out.println("Token validated successfully: " + token);

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
                System.out.println("🔍 Calling user-service with RestTemplate");

                String url = "http://localhost:8082/auth/validate-token?token=" +
                        URLEncoder.encode(token, StandardCharsets.UTF_8);

                ResponseEntity<Boolean> response = restTemplate.getForEntity(
                        url, Boolean.class);

                System.out.println("✅ RestTemplate response: " + response.getStatusCode());
                System.out.println("✅ Body: " + response.getBody());

                return Boolean.TRUE.equals(response.getBody()) ? false : true;
                // true = está na blacklist, false = não está

            } catch (Exception e) {
                System.out.println("❌ RestTemplate error: " + e.getClass().getName());
                System.out.println("Error: " + e.getMessage());
                return false; // Não bloqueia em caso de erro
            }
        }).subscribeOn(Schedulers.boundedElastic()); // Executa em thread separada
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