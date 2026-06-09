package yusufjon.uz.authsessionstore.security;

import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import yusufjon.uz.authsessionstore.user.Role;
import yusufjon.uz.authsessionstore.user.User;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class JwtServiceTest {

    private JwtService jwtService;
    private User user;
    private UUID sessionId;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();
        String secret = Base64.getEncoder().encodeToString(
                "test-jwt-secret-test-jwt-secret-test-jwt-secret-12345"
                        .getBytes(StandardCharsets.UTF_8)
        );

        ReflectionTestUtils.setField(jwtService, "secret", secret);
        ReflectionTestUtils.setField(jwtService, "accessTokenExpirationMinutes", 15L);
        ReflectionTestUtils.setField(jwtService, "refreshTokenExpirationDays", 7L);

        user = User.builder()
                .id(1L)
                .fullName("Test User")
                .email("user@example.com")
                .password("encoded-password")
                .role(Role.USER)
                .enabled(true)
                .build();
        sessionId = UUID.randomUUID();
    }

    @Test
    void generateAccessTokenShouldProduceTokenWithExpectedClaims() {
        String token = jwtService.generateAccessToken(user, sessionId);

        Claims claims = jwtService.parseClaims(token);

        assertThat(claims.getSubject()).isEqualTo("user@example.com");
        assertThat(claims.get("userId", Number.class).longValue()).isEqualTo(1L);
        assertThat(claims.get("role", String.class)).isEqualTo("USER");
        assertThat(claims.get("sessionId", String.class)).isEqualTo(sessionId.toString());
        assertThat(claims.get("tokenType", String.class)).isEqualTo("access");
        assertThat(claims.getId()).isNotBlank();
        assertThat(claims.getExpiration()).isAfter(claims.getIssuedAt());
    }

    @Test
    void generateRefreshTokenShouldProduceTokenWithTokenTypeRefresh() {
        String token = jwtService.generateRefreshToken(user, sessionId);

        Claims claims = jwtService.parseClaims(token);

        assertThat(claims.getSubject()).isEqualTo("user@example.com");
        assertThat(claims.get("sessionId", String.class)).isEqualTo(sessionId.toString());
        assertThat(claims.get("tokenType", String.class)).isEqualTo("refresh");
    }

    @Test
    void parseClaimsShouldParseValidToken() {
        String token = jwtService.generateAccessToken(user, sessionId);

        Claims claims = jwtService.parseClaims(token);

        assertThat(claims.getSubject()).isEqualTo("user@example.com");
        assertThat(claims.getId()).isNotBlank();
    }

    @Test
    void extractUsernameShouldReturnEmail() {
        String token = jwtService.generateAccessToken(user, sessionId);

        assertThat(jwtService.extractUsername(token)).isEqualTo("user@example.com");
    }

    @Test
    void extractSessionIdShouldReturnSessionUuid() {
        String token = jwtService.generateAccessToken(user, sessionId);

        assertThat(jwtService.extractSessionId(token)).isEqualTo(sessionId);
    }

    @Test
    void extractUserIdShouldReturnUserId() {
        String token = jwtService.generateAccessToken(user, sessionId);

        assertThat(jwtService.extractUserId(token)).isEqualTo(1L);
    }

    @Test
    void extractTokenTypeShouldReturnTokenType() {
        String token = jwtService.generateRefreshToken(user, sessionId);

        assertThat(jwtService.extractTokenType(token)).isEqualTo("refresh");
    }

    @Test
    void getRemainingTtlShouldReturnPositiveDurationForNonExpiredToken() {
        String token = jwtService.generateAccessToken(user, sessionId);

        Duration remainingTtl = jwtService.getRemainingTtl(token);

        assertThat(remainingTtl).isPositive();
        assertThat(remainingTtl).isLessThanOrEqualTo(Duration.ofMinutes(15));
    }
}
