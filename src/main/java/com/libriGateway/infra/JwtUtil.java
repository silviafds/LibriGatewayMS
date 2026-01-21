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

/** Utility class for JWT token handling.
 *
 * This class provides helper methods to validate JWT tokens,
 * check expiration, and extract claims such as user identifier
 * and subject information.
 *
 * It is primarily used by the API Gateway to perform local
 * token validation before forwarding requests to downstream services.
 */
@Component
public class JwtUtil {

    @Value("${jwt.secret:my-very-strong-secret-key-of-32-characters}")
    private String secret;

    private SecretKey key;


    /** Initializes the cryptographic key used to verify JWT signatures.
     */
    @PostConstruct
    public void init() {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Extracts all claims from the given JWT token.
     *
     * @param token JWT token
     * @return Claims contained in the token
     * @throws RuntimeException if the token is invalid
     */
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

    /**
     * Checks whether the token has expired.
     *
     * @param token JWT token
     * @return true if the token is expired or cannot be processed
     */
    private boolean isTokenExpired(String token) {
        try {
            return getAllClaimsFromToken(token).getExpiration().before(new Date());
        } catch (Exception e) {
            return true; // If you can't read it, consider it expired.
        }
    }

    /**
     * Determines whether the token is invalid.
     *
     * @param token JWT token
     * @return true if the token is expired or invalid
     */
    public boolean isInvalid(String token) {
        try {
            return isTokenExpired(token);
        } catch (Exception e) {
            return true;
        }
    }

    /**
     * Extracts the subject (email or username) from the JWT token.
     *
     * @param token JWT token
     * @return subject value or null if extraction fails
     */
    public String extractEmail(String token) {
        try {
            return getAllClaimsFromToken(token).get("sub", String.class);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Extracts the user identifier from the JWT token.
     *
     * @param token JWT token
     * @return user ID or null if extraction fails
     */
    public String extractUserId(String token) {
        try {
            return getAllClaimsFromToken(token).get("userId", String.class);
        } catch (Exception e) {
            return null;
        }
    }
}