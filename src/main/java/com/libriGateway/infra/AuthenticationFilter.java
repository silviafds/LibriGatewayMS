package com.libriGateway.infra;

import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
@RequiredArgsConstructor
public class AuthenticationFilter implements GatewayFilter {

    private final RouterValidator routerValidator;
    private final JwtUtil jwtUtil;

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

        if (jwtUtil.isInvalid(token)) {
            System.out.println("Invalid token");
            return onError(exchange, HttpStatus.FORBIDDEN, "Token inválido ou expirado");
        }

        System.out.println("Token validated successfully");
        return chain.filter(exchange);
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