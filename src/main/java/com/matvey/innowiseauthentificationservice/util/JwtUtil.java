package com.matvey.innowiseauthentificationservice.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import java.util.function.Function;

@Component
public class JwtUtil {

    @Value("${jwt.expiration:900000}")
    private long accessTokenExpiration;

    @Value("${jwt.refresh-expiration:604800000}")
    private long refreshTokenExpiration;

    private final KeyPair keyPair;

    public JwtUtil() {
        this.keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    private PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }

    public String generateAccessToken(UUID userId, String role) {
        return Jwts.builder()
                .subject(userId.toString())
                .claim("role", "ROLE_" + role)
                .id(UUID.randomUUID().toString())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + accessTokenExpiration))
                .signWith(getPrivateKey())
                .compact();
    }

    public String generateRefreshToken(UUID userId) {
        return Jwts.builder()
                .subject(userId.toString())
                .id(UUID.randomUUID().toString())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + refreshTokenExpiration))
                .signWith(getPrivateKey())
                .compact();
    }

    public UUID extractUserId(String token) {
        return UUID.fromString(extractClaim(token, Claims::getSubject));
    }

    public String extractRole(String token) {
        return extractClaim(token, claims -> claims.get("role", String.class));
    }

    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(getPublicKey())
                    .build()
                    .parseSignedClaims(token);
            return !isTokenExpired(token);
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getPublicKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String getPublicKeyPem() {
        PublicKey publicKey = getPublicKey();
        String publicKeyEncoded = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" +
                publicKeyEncoded +
                "\n-----END PUBLIC KEY-----";
    }
}
