package com.libriGateway.infra;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Predicate;

@Component
public class RouterValidator {

    // Lista de endpoints PÚBLICOS
    public static final List<String> publicEndpoints = List.of(
            "/auth/register",
            "/auth/login",
            "/actuator/health",
            "/eureka"
    );

    public Predicate<ServerHttpRequest> isSecured =
            request -> publicEndpoints.stream()
                    .noneMatch(uri -> request.getURI().getPath().equals(uri));
}