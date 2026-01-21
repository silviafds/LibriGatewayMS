package com.libriGateway.security;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Predicate;

/**
 * Route validation component used by the API Gateway.
 *
 * This class defines which endpoints are public and provides
 * a predicate to determine whether an incoming request
 * requires authentication.
 */
@Component
public class RouterValidator {

    /**
     * List of public endpoints that do not require authentication.
     */
    public static final List<String> publicEndpoints = List.of(
            "/auth/register",
            "/auth/login",
            "/actuator/health",
            "/eureka"
    );

    /**
     * Predicate that checks if a request is secured.
     *
     * @return true if the request requires authentication,
     *         false if the endpoint is public
     */
    public Predicate<ServerHttpRequest> isSecured =
            request -> publicEndpoints.stream()
                    .noneMatch(uri ->
                            request.getURI().getPath().equals(uri));
}