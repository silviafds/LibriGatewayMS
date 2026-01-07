package com.libriGateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class LibriGatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(LibriGatewayApplication.class, args);
	}

}
