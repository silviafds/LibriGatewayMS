package com.libriGateway.config;

import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.core5.util.Timeout;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

/**
 * RestTemplate configuration for inter-service communication.
 *
 * This configuration provides a load-balanced RestTemplate
 * with connection pooling and timeout settings, allowing
 * the API Gateway to communicate with downstream services
 * using service discovery (Eureka / LoadBalancer).
 */
@Configuration
public class RestTemplateConfig {

    /**
     * Creates a load-balanced RestTemplate with connection pooling
     * and timeout configuration.
     *
     * @return configured RestTemplate instance
     */
    @Bean
    @LoadBalanced
    public RestTemplate loadBalancedRestTemplate() {

        // Manages and reuses HTTP connections
        PoolingHttpClientConnectionManager connectionManager =
                new PoolingHttpClientConnectionManager();
        connectionManager.setMaxTotal(100);
        connectionManager.setDefaultMaxPerRoute(20);

        // Defines HTTP timeout settings
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(Timeout.ofSeconds(3))
                .setResponseTimeout(Timeout.ofSeconds(3))
                .setConnectionRequestTimeout(Timeout.ofSeconds(3))
                .build();

        // Builds the HTTP client with pooling and timeouts
        CloseableHttpClient httpClient = HttpClients.custom()
                .setConnectionManager(connectionManager)
                .setDefaultRequestConfig(requestConfig)
                .build();

        // Integrates HttpClient with RestTemplate
        HttpComponentsClientHttpRequestFactory factory =
                new HttpComponentsClientHttpRequestFactory(httpClient);

        return new RestTemplate(factory);
    }
}