package yusufjon.uz.authsessionstore.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import yusufjon.uz.authsessionstore.user.User;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {

    @Value("${app.jwt.secret}")
    private String secret;

    @Value("${app.jwt.access-token-expiration-minutes}")
    private long accessTokenExpirationMinutes;

    @Value("${app.jwt.refresh-token-expiration-days}")
    private long refreshTokenExpirationDays;

    public String generateAccessToken(User user, UUID sessionId) {
        return generateToken(user, sessionId, getAccessTokenTtl(), "access");
    }

    public String generateRefreshToken(User user, UUID sessionId) {
        return generateToken(user, sessionId, getRefreshTokenTtl(), "refresh");
    }

    public Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        Claims claims = parseClaims(token);
        String userName = claims.getSubject();

        return userName.equals(userDetails.getUsername()) && !isExpired(claims);
    }

    public String extractUsername(String token) {
        return parseClaims(token).getSubject();
    }

    public String extractJti(String token) {
        return parseClaims(token).getId();
    }

    public String extractTokenType(String token) {
        return parseClaims(token).get("tokenType", String.class);
    }

    public UUID extractSessionId(String token) {
        String sessionId = parseClaims(token).get("sessionId", String.class);
        return UUID.fromString(sessionId);
    }

    public Long extractUserId(String token) {
        Number userId = parseClaims(token).get("userId", Number.class);
        return userId.longValue();
    }

    public Duration getRemainingTtl(String token) {
        Claims claims = parseClaims(token);
        return getRemainingTtl(claims);
    }

    public Duration getRemainingTtl(Claims claims) {
        Instant expiration = claims.getExpiration().toInstant();
        Duration ttl = Duration.between(Instant.now(), expiration);

        if (ttl.isNegative()) {
            return Duration.ZERO;
        }

        return ttl;
    }

    public Duration getAccessTokenTtl() {
        return Duration.ofMinutes(accessTokenExpirationMinutes);
    }

    public Duration getRefreshTokenTtl() {
        return Duration.ofDays(refreshTokenExpirationDays);
    }

    private String generateToken(User user, UUID sessionId, Duration ttl, String tokenType) {
        Instant now = Instant.now();
        Instant expiration = now.plus(ttl);

        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(user.getEmail())
                .claim("userId", user.getId())
                .claim("role", user.getRole().name())
                .claim("sessionId", sessionId.toString())
                .claim("tokenType", tokenType)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiration))
                .signWith(getSigningKey())
                .compact();
    }

    private boolean isExpired(Claims claims) {
        return claims.getExpiration().before(new Date());
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
