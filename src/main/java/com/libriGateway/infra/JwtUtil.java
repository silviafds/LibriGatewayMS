package com.libriGateway.infra;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtil {

    @Value("${jwt.secret:my-very-strong-secret-key-of-32-characters}")
    private String secret;

    private SecretKey key;

    @PostConstruct
    public void init() {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public Claims getAllClaimsFromToken(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (Exception e) {
            throw new RuntimeException("Invalid token", e);
        }
    }

    private boolean isTokenExpired(String token) {
        try {
            return getAllClaimsFromToken(token).getExpiration().before(new Date());
        } catch (Exception e) {
            return true; // Se não consegue ler, considera expirado
        }
    }

    public boolean isInvalid(String token) {
        try {
            return isTokenExpired(token);
        } catch (Exception e) {
            return true;
        }
    }

    // Novo método para extrair email
    public String extractEmail(String token) {
        try {
            return getAllClaimsFromToken(token).get("sub", String.class);
        } catch (Exception e) {
            return null;
        }
    }

    // Novo método para extrair userId
    public String extractUserId(String token) {
        try {
            return getAllClaimsFromToken(token).get("userId", String.class);
        } catch (Exception e) {
            return null;
        }
    }
}