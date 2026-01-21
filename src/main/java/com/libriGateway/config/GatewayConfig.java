package com.libriGateway.config;

import com.libriGateway.filter.AuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Gateway route configuration.
 *
 * This class defines all API Gateway routes and maps incoming
 * HTTP requests to their corresponding downstream microservices.
 *
 * Each route applies the AuthenticationFilter, which determines
 * whether the request requires JWT validation based on the route.
 *
 * Service discovery and load balancing are handled through
 * Eureka using the "lb://" URI scheme.
 */
@Configuration
@RequiredArgsConstructor
public class GatewayConfig {

    private final AuthenticationFilter filter;


     /** Configures and registers the API Gateway routes.
     *
     * Public and secured routes are defined here, along with
     * their target microservices.
     *
     * @param builder RouteLocator builder provided by Spring Cloud Gateway
     * @return configured RouteLocator instance
     */
    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                // PUBLIC route: User registration
                .route("user-register", r -> r
                        .path("/auth/register")
                        .and()
                        .method("POST")
                        .filters(f -> f.filter(filter))
                        .uri("lb://user-service"))  // LoadBalancer + Eureka

                // PUBLIC route: User login
                .route("user-login", r -> r
                        .path("/auth/login")
                        .and()
                        .method("POST")
                        .filters(f -> f.filter(filter))
                        .uri("lb://user-service"))

                // PROTECTED routes: Other auth endpoints
                .route("user-protected", r -> r
                        .path("/auth/**")
                        .filters(f -> f.filter(filter))
                        .uri("lb://user-service"))

                // PROTECTED route: Catalog service
                .route("catalog-service", r -> r
                        .path("/books/**")
                        .filters(f -> f.filter(filter))
                        .uri("lb://catalog-service"))

                // PROTECTED route: Review service
                .route("review-service", r -> r
                        .path("/review/**")
                        .filters(f -> f.filter(filter))
                        .uri("lb://review-service"))

                .build();
    }
}