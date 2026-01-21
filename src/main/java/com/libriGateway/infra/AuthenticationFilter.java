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

/**  The AuthenticationFilter acts as a security filter in the API Gateway, being responsible for intercepting requests
 *  destined for protected routes, extracting and validating JWT tokens, verifying their revocation through the
 *  authentication service, and applying resilience mechanisms to ensure system stability.
 */
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
            @LoadBalanced RestTemplate restTemplate) {

        this.routerValidator = routerValidator;
        this.jwtUtil = jwtUtil;
        this.restTemplate = restTemplate;

        // Instância específica do Circuit Breaker
        this.circuitBreaker = circuitBreakerRegistry
                .circuitBreaker("userServiceTokenValidation");

        System.out.println("✅ AuthenticationFilter inicializado com RestTemplate com LoadBalancer");
    }

    /** API Gateway authentication filter.
     *
     * Intercepts all incoming requests and determines whether the accessed
     * route is public or secured.
     *
     * Public routes are forwarded without authentication.
     * Secured routes trigger the JWT token validation process.
     *
     * @param exchange HTTP request/response context
     * @param chain    Gateway filter chain
     * @return Mono representing the filter execution
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();
        String method = request.getMethod().name();

        System.out.println("Request: " + method + " " + path);

        if (!routerValidator.isSecured.test(request)) { // Verify route is public
            System.out.println("Public route: " + path);
            return chain.filter(exchange);
        }

        return validateTokenAndProceed(exchange, chain); // For protected routes, validate the token.
    }

     /** Extracts the authentication token from the request and initiates
     * the validation process.
     *
     * The token is first retrieved from the Authorization header.
     * If not present and the request method is POST or PUT, the token
     * is extracted from the request body.
     *
     * If no token is found, the request is rejected with an unauthorized response.
     *
     * @param exchange HTTP request/response context
     * @param chain    Gateway filter chain
     * @return Mono representing the continuation or rejection of the request
     */
    private Mono<Void> validateTokenAndProceed(ServerWebExchange exchange,
                                               GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        List<String> authHeaders = request.getHeaders().get("Authorization");  // Try to get the header token first
        String token = null;

        if (authHeaders != null && !authHeaders.isEmpty()) {
            String authHeader = authHeaders.get(0);

            if (authHeader.startsWith("Bearer ")) {
                token = authHeader.substring(7).trim();
            } else {
                // If it doesn't start with "Bearer", it's assumed to be a pure token in the header
                token = authHeader.trim();
            }
        }
        // If you can't find it the header, try extracting it from the body (for POST/PUT)
        if (token == null && (HttpMethod.POST.equals(request.getMethod()) ||
                HttpMethod.PUT.equals(request.getMethod()))) {
            return extractTokenFromBody(exchange, chain);
        } else if (token == null) {
            System.out.println("Missing Authorization header or token");
            return onError(exchange, HttpStatus.UNAUTHORIZED, "Token não fornecido");
        }

        return validateTokenAndContinue(token, exchange, chain);
    }

     /** Extracts the authentication token from the request body.
     *
     * This method reads the request body and attempts to retrieve the token
     * from common JSON fields such as "token", "accessToken", or "authorization".
     *
     * If a valid token is found, the validation process continues.
     * If the token is missing or the body cannot be processed, the request
     * is rejected with an appropriate error response.
     *
     * @param exchange HTTP request/response context
     * @param chain    Gateway filter chain
     * @return Mono representing the continuation or rejection of the request
     */
    private Mono<Void> extractTokenFromBody(ServerWebExchange exchange,
                                            GatewayFilterChain chain) {

        // CachedBodyServerHttpRequestWrapper it is necessary to read the body multiple times
        return DataBufferUtils.join(exchange.getRequest().getBody())
                .flatMap(dataBuffer -> {
                    byte[] bytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bytes);
                    DataBufferUtils.release(dataBuffer);

                    String body = new String(bytes, StandardCharsets.UTF_8);

                    try {
                        // Attempts to extract token from JSON body.
                        ObjectMapper mapper = new ObjectMapper();
                        JsonNode jsonNode = mapper.readTree(body);

                        String token = null;

                        // Search for common fields that may contain the token.
                        if (jsonNode.has("token")) {
                            token = jsonNode.get("token").asText();
                        } else if (jsonNode.has("accessToken")) {
                            token = jsonNode.get("accessToken").asText();
                        } else if (jsonNode.has("authorization")) {
                            token = jsonNode.get("authorization").asText();
                        }

                        if (token != null && !token.isEmpty()) {
                            if (token.startsWith("Bearer ")) {  // Remove "Bearer " if present
                                token = token.substring(7).trim();
                            }

                            return validateTokenAndContinue(token, exchange, chain);  // Validate the token.
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

     /** Validates the JWT token and forwards the request if authentication succeeds.
     *
     * This method performs a local validation of the token to check its
     * integrity and expiration. If the token is valid, it verifies whether
     * the token has been revoked by checking it against the authentication
     * service blacklist.
     *
     * If the token passes all validations, the request is forwarded to the
     * downstream microservice with the Authorization header attached.
     * Otherwise, the request is rejected with an appropriate error response.
     *
     * @param token    JWT token extracted from the request
     * @param exchange HTTP request/response context
     * @param chain    Gateway filter chain
     * @return Mono representing the continuation or rejection of the request
     */
    private Mono<Void> validateTokenAndContinue(String token,
                                                ServerWebExchange exchange,
                                                GatewayFilterChain chain) {

        if (jwtUtil.isInvalid(token)) { // 1. Checks if the token is valid (not expired).
            System.out.println("❌ Invalid token (expired or malformed)");
            return onError(exchange, HttpStatus.FORBIDDEN, "Token inválido ou expirado");
        }

        System.out.println("✅ Token JWT válido localmente");

        // 2. Checks if the token is on the blacklist (logout).
        return checkTokenBlacklist(token).flatMap(shouldBlock -> {
            if (shouldBlock) {
                System.out.println("❌ Token bloqueado - Razão: " +
                        (shouldBlock ? "Blacklist ou serviço indisponível" : "Desconhecido"));
                return onError(exchange, HttpStatus.UNAUTHORIZED,
                        "Token invalidado ou serviço de autenticação indisponível");
            }

            System.out.println("✅ Token validado com sucesso (não está na blacklist)");
            System.out.println("Token: " + token);

            // Add the token as a header for the downstream microservice.
            ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                    .header("Authorization", "Bearer " + token)
                    .build();

            return chain.filter(exchange.mutate().request(mutatedRequest).build());
        });
    }

     /** Checks whether the given JWT token is blacklisted or revoked.
     *
     * This method calls the authentication service to validate the token
     * against a blacklist (e.g. logout scenarios). The call is protected
     * by a Circuit Breaker to prevent cascading failures.
     *
     * If the authentication service is unavailable or returns an error,
     * the request is blocked as a security precaution.
     *
     * @param token JWT token to be validated
     * @return Mono emitting {@code true} if the request should be blocked,
     *         or {@code false} if the token is valid and not blacklisted
     */
    private Mono<Boolean> checkTokenBlacklist(String token) {
        return Mono.fromCallable(() -> {
            try {
                // Using Circuit Breaker
                Boolean result = circuitBreaker.executeSupplier(() -> {
                    // URL with service discovery (don't need IP)
                    String url = "http://user-service/auth/validate-token?token=" +
                            URLEncoder.encode(token, StandardCharsets.UTF_8);

                    System.out.println("🔍 Chamando user-service via LoadBalancer: " + url);

                    ResponseEntity<Boolean> response = restTemplate.getForEntity(
                            url, Boolean.class);

                    if (!response.getStatusCode().is2xxSuccessful()) {
                        throw new RuntimeException("Serviço retornou erro: " +
                                response.getStatusCode());
                    }

                    // IMPORTANT: We've reversed the logic here
                    // API returns TRUE if token is valid, FALSE if it's on the blacklist
                    // We want to return TRUE if it should be BLOCKED
                    Boolean apiResponse = response.getBody();
                    System.out.println("✅ Resposta do user-service: " + apiResponse);
                    return Boolean.FALSE.equals(apiResponse); // TRUE = bloquear
                });

                return result;

            } catch (Exception e) {
                System.out.println("❌ Erro ao validar token no user-service: " + e.getClass().getSimpleName());
                System.out.println("Mensagem: " + e.getMessage());
                System.out.println("⚠️  Serviço de autenticação indisponível - BLOQUEANDO requisição");
                return true; // BLOCK in case of error
            }
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /** Builds and returns a standardized JSON error response.
     *
     * This method sets the HTTP status code and content type,
     * creates a JSON response body with error details, and
     * writes it to the response stream.
     *
     * @param exchange HTTP request/response context
     * @param status   HTTP status to be returned
     * @param message  Custom error message describing the failure
     * @return Mono representing the completion of the response writing
     */
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