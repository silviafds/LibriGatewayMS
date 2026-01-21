# 📘 API Gateway – Microservices Architecture

##  📌 Overview

This project implements an **API Gateway** using **Spring Cloud Gateway** as the single entry point for a microservices-based architecture.

The Gateway is responsible for:

- Routing requests to the appropriate microservice

- Centralized authentication using JWT

- Token validation and blacklist verification

- Load balancing via service discovery

- Resilience using Circuit Breaker and Retry mechanisms

## 🏗️ Architecture

The system follows a **microservices architecture** with the following components:

- API Gateway

- User Service

- Catalog Service

- Bookshelf Service (review in moment)

- Eureka Server (Service Discovery)

```` 
Client
   ↓
API Gateway
   ↓
+-------------------+
| Service Discovery |
|     (Eureka)      |
+-------------------+
   ↓
Microservices
````

## 🚪 API Gateway Responsibilities

The API Gateway provides:

- Centralized routing

- JWT authentication

- Public and protected route validation

- Token blacklist verification via User Service

- Fault tolerance using Circuit Breaker

- Client-side load balancing

## **🔐 Security**

### **JWT Authentication**

- All protected routes require a valid JWT token.

- The token is validated locally (expiration check).

- The token is also validated remotely via the User Service to ensure it is not blacklisted (logout).

### **Public Routes**

The following endpoints are publicly accessible:

- ``POST /auth/register``

- ``POST /auth/login``

- ``/actuator/health``

- ``/eureka``

All other routes are considered **secured** and require authentication.

## **🧠 Authentication Flow**

1. Client sends a request to the API Gateway.

2. The Gateway checks whether the route is public or protected.

3. For protected routes:

    - The JWT token is extracted from the request header or body.

    - The token expiration is validated locally.

    - The token is validated against the User Service blacklist.

4. If valid, the request is forwarded to the target microservice.

5. If invalid, the Gateway returns an error response.

## **🔄 Service Discovery & Load Balancing**

- The Gateway uses Eureka for service discovery.

- All service calls use logical service names (e.g. ``lb://user-service``).

- Load balancing is handled automatically via Spring Cloud LoadBalancer.

## **🛡️ Resilience & Fault Tolerance**
### **Circuit Breaker (Resilience4j)**

- Prevents cascading failures when the User Service is unavailable.

- Automatically opens the circuit after a defined failure threshold.

- Falls back to blocking requests when authentication cannot be verified.

### **Retry Mechanism**

- Automatically retries failed requests based on configured policies.

- Improves reliability in transient failure scenarios.

## **⚙️ Technologies Used**

- Java 17+

- Spring Boot

- Spring Cloud Gateway (Reactive)

- Spring Cloud Eureka

- Spring Cloud LoadBalancer

- Resilience4j

- JWT (JJWT)

- Reactor (Mono / Flux)

- Apache HttpClient

## **🚀 How to Run**
### **Prerequisites**

- Java 17+

- Maven

- Eureka Server running on port 8761

- All microservices registered in Eureka

### **Steps**

1. Start the Eureka Server

2. Start the User Service

3. Start other microservices (Catalog, Review, etc.)

4. Start the API Gateway

The Gateway will run on:

````http://localhost:8089````

## **📂 Project Structure**

````
api-gateway
├── config
│   ├── GatewayConfig
│   ├── RestTemplateConfig
├── filter
│   └── AuthenticationFilter
├── security
│   ├── JwtUtil
│   └── RouterValidator
├── application.yml
└── README.md
````

## **✅ Key Features Summary**

- Centralized authentication

- Secure JWT handling

- Service discovery integration

- Load-balanced inter-service communication

- Fault tolerance with Circuit Breaker

- Clean separation of responsibilities

## **📌 Notes**

This Gateway is designed to be:

- Scalable

- Secure

- Easy to extend

- Suitable for real-world microservice environments
