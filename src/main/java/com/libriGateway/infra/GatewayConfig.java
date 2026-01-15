package com.libriGateway.infra;


import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class GatewayConfig {

    private final AuthenticationFilter filter;

    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                // Rota PÚBLICA: Registro de usuário
                .route("user-register", r -> r
                        .path("/auth/register")
                        .and()
                        .method("POST")
                        .filters(f -> f.filter(filter))
                        .uri("lb://user-service"))  // LoadBalancer + Eureka

                // Rota PÚBLICA: Login
                .route("user-login", r -> r
                        .path("/auth/login")
                        .and()
                        .method("POST")
                        .filters(f -> f.filter(filter))
                        .uri("lb://user-service"))

                // Rotas PROTEGIDAS: Outras rotas de auth
                .route("user-protected", r -> r
                        .path("/auth/**")
                        .filters(f -> f.filter(filter))
                        .uri("lb://user-service"))

                // Rota para catalog (protegida)
                .route("catalog-service", r -> r
                        .path("/books/**")
                        .filters(f -> f.filter(filter))
                        .uri("lb://catalog-service"))

                // Rota para reviews (protegida)
                .route("review-service", r -> r
                        .path("/review/**")
                        .filters(f -> f.filter(filter))
                        .uri("lb://review-service"))

                .build();
    }
}