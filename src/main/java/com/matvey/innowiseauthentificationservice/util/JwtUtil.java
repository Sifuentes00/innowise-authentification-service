package com.matvey.innowiseauthentificationservice.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import java.util.function.Function;

@Getter
@Component
public class JwtUtil {

    @Value("${jwt.expiration}")
    private long accessTokenExpiration;

    @Value("${jwt.refresh-expiration}")
    private long refreshTokenExpiration;

    @Value("${jwt.keys-path:/app/keys/}")
    private String keysPath;

    private final KeyPair keyPair;

    public JwtUtil() {
        this.keyPair = loadOrGenerateKeys();
    }

    private KeyPair loadOrGenerateKeys() {
        try {
            Path keysDir = Paths.get(keysPath);
            if (!Files.exists(keysDir)) {
                Files.createDirectories(keysDir);
            }

            Path privateKeyPath = keysDir.resolve("private.key");
            Path publicKeyPath = keysDir.resolve("public.key");

            if (Files.exists(privateKeyPath) && Files.exists(publicKeyPath)) {
                try {
                    return loadKeysFromFile(privateKeyPath, publicKeyPath);
                } catch (Exception e) {
                    KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
                    saveKeysToFile(keyPair, privateKeyPath, publicKeyPath);
                    return keyPair;
                }
            } else {
                KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
                saveKeysToFile(keyPair, privateKeyPath, publicKeyPath);
                return keyPair;
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to load or generate keys", e);
        }
    }

    private KeyPair loadKeysFromFile(Path privateKeyPath, Path publicKeyPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        String privateKeyPem = new String(Files.readAllBytes(privateKeyPath))
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        String publicKeyPem = new String(Files.readAllBytes(publicKeyPath))
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyPem);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyPem);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        return new KeyPair(publicKey, privateKey);
    }

    private void saveKeysToFile(KeyPair keyPair, Path privateKeyPath, Path publicKeyPath) throws IOException {
        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();
        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();

        String privateKeyPem = "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getEncoder().encodeToString(privateKeyBytes) +
                "\n-----END PRIVATE KEY-----";

        String publicKeyPem = "-----BEGIN PUBLIC KEY-----\n" +
                Base64.getEncoder().encodeToString(publicKeyBytes) +
                "\n-----END PUBLIC KEY-----";

        Files.write(privateKeyPath, privateKeyPem.getBytes());
        Files.write(publicKeyPath, publicKeyPem.getBytes());
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
                .claim("token-type", "access")
                .id(UUID.randomUUID().toString())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + accessTokenExpiration))
                .signWith(getPrivateKey())
                .compact();
    }

    public String generateRefreshToken(UUID userId) {
        return Jwts.builder()
                .subject(userId.toString())
                .claim("token-type", "refresh")
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

    public String extractTokenType(String token) {
        return extractClaim(token, claims -> claims.get("token-type", String.class));
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
