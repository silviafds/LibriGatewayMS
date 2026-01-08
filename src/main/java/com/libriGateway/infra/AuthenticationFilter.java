package com.libriGateway.infra;

import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.core5.util.Timeout;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
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

        // Verifica header Authorization
        List<String> authHeaders = request.getHeaders().get("Authorization");

        if (authHeaders == null || authHeaders.isEmpty()) {
            System.out.println("Missing Authorization header");
            return onError(exchange, HttpStatus.UNAUTHORIZED, "Token não fornecido");
        }

        String authHeader = authHeaders.get(0);

        if (!authHeader.startsWith("Bearer ")) {
            System.out.println("Invalid Authorization format");
            return onError(exchange, HttpStatus.UNAUTHORIZED, "Formato de token inválido");
        }

        String token = authHeader.substring(7).trim();

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

            System.out.println("Token validated successfully");
            return chain.filter(exchange);
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