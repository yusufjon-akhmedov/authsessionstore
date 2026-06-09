package yusufjon.uz.authsessionstore.redis;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import yusufjon.uz.authsessionstore.session.SessionInfo;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = RedisTokenServiceTest.RedisTestConfig.class)
@Testcontainers
@ActiveProfiles("test")
class RedisTokenServiceTest {

    private static final int REDIS_PORT = 6379;

    @Container
    static final GenericContainer<?> redis = new GenericContainer<>("redis:7-alpine")
            .withExposedPorts(REDIS_PORT);

    @DynamicPropertySource
    static void redisProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.data.redis.host", redis::getHost);
        registry.add("spring.data.redis.port", () -> redis.getMappedPort(REDIS_PORT));
        registry.add("spring.data.redis.repositories.enabled", () -> false);
    }

    @Autowired
    private RedisTokenService redisTokenService;

    @Autowired
    private StringRedisTemplate redisTemplate;

    @BeforeEach
    void setUp() {
        flushRedis();
    }

    @Test
    void saveRefreshTokenAndFindRefreshTokenShouldWork() {
        UUID sessionId = UUID.randomUUID();

        redisTokenService.saveRefreshToken(1L, sessionId, "refresh-token", Duration.ofMinutes(5));

        Optional<String> result = redisTokenService.findRefreshToken(1L, sessionId);

        assertThat(result).contains("refresh-token");
    }

    @Test
    void saveSessionAndFindSessionsByUserIdShouldWork() {
        UUID sessionId = UUID.randomUUID();
        Instant now = Instant.now();
        SessionInfo sessionInfo = new SessionInfo(
                sessionId,
                1L,
                "user@example.com",
                "127.0.0.1",
                "JUnit",
                now,
                now.plusSeconds(3600)
        );

        redisTokenService.saveSession(sessionInfo, Duration.ofMinutes(5));

        List<SessionInfo> sessions = redisTokenService.findSessionsByUserId(1L);

        assertThat(sessions).hasSize(1);
        assertThat(sessions.getFirst().sessionId()).isEqualTo(sessionId);
        assertThat(sessions.getFirst().userId()).isEqualTo(1L);
        assertThat(sessions.getFirst().email()).isEqualTo("user@example.com");
        assertThat(sessions.getFirst().ipAddress()).isEqualTo("127.0.0.1");
        assertThat(sessions.getFirst().userAgent()).isEqualTo("JUnit");
    }

    @Test
    void deleteSessionShouldDeleteBothSessionAndRefreshToken() {
        UUID sessionId = UUID.randomUUID();
        SessionInfo sessionInfo = sessionInfo(1L, "user@example.com", sessionId);

        redisTokenService.saveRefreshToken(1L, sessionId, "refresh-token", Duration.ofMinutes(5));
        redisTokenService.saveSession(sessionInfo, Duration.ofMinutes(5));

        redisTokenService.deleteSession(1L, sessionId);

        assertThat(redisTokenService.findRefreshToken(1L, sessionId)).isEmpty();
        assertThat(redisTokenService.findSessionsByUserId(1L)).isEmpty();
    }

    @Test
    void deleteAllSessionsShouldDeleteAllSessionsAndRefreshTokensForUser() {
        UUID firstSessionId = UUID.randomUUID();
        UUID secondSessionId = UUID.randomUUID();

        redisTokenService.saveRefreshToken(1L, firstSessionId, "first-refresh-token", Duration.ofMinutes(5));
        redisTokenService.saveRefreshToken(1L, secondSessionId, "second-refresh-token", Duration.ofMinutes(5));
        redisTokenService.saveSession(
                sessionInfo(1L, "user@example.com", firstSessionId),
                Duration.ofMinutes(5)
        );
        redisTokenService.saveSession(
                sessionInfo(1L, "user@example.com", secondSessionId),
                Duration.ofMinutes(5)
        );

        redisTokenService.deleteAllSessions(1L);

        assertThat(redisTokenService.findRefreshToken(1L, firstSessionId)).isEmpty();
        assertThat(redisTokenService.findRefreshToken(1L, secondSessionId)).isEmpty();
        assertThat(redisTokenService.findSessionsByUserId(1L)).isEmpty();
    }

    @Test
    void blacklistAccessTokenAndIsAccessTokenBlacklistedShouldWork() {
        redisTokenService.blackListAccessToken("jwt-id", Duration.ofMinutes(5));

        assertThat(redisTokenService.isAccessTokenBlackListed("jwt-id")).isTrue();
        assertThat(redisTokenService.isAccessTokenBlackListed("other-jwt-id")).isFalse();
    }

    @Test
    void saveOtpFindOtpAndDeleteOtpShouldWork() {
        redisTokenService.saveOtp("USER@example.com", "123456", Duration.ofMinutes(5));

        assertThat(redisTokenService.findOtp("user@example.com")).contains("123456");

        redisTokenService.deleteOtp("user@example.com");

        assertThat(redisTokenService.findOtp("user@example.com")).isEmpty();
    }

    @Test
    void savePasswordResetTokenFindPasswordResetUserIdAndDeletePasswordResetTokenShouldWork() {
        redisTokenService.savePasswordResetToken("reset-token", 1L, Duration.ofMinutes(5));

        assertThat(redisTokenService.findPasswordResetUserId("reset-token")).contains(1L);

        redisTokenService.deletePasswordResetToken("reset-token");

        assertThat(redisTokenService.findPasswordResetUserId("reset-token")).isEmpty();
    }

    private void flushRedis() {
        redisTemplate.execute((RedisCallback<Void>) connection -> {
            connection.serverCommands().flushDb();
            return null;
        });
    }

    private SessionInfo sessionInfo(Long userId, String email, UUID sessionId) {
        Instant now = Instant.now();
        return new SessionInfo(
                sessionId,
                userId,
                email,
                "127.0.0.1",
                "JUnit",
                now,
                now.plusSeconds(3600)
        );
    }

    @Configuration
    static class RedisTestConfig {

        @Bean
        RedisConnectionFactory redisConnectionFactory(
                @Value("${spring.data.redis.host}") String host,
                @Value("${spring.data.redis.port}") int port
        ) {
            LettuceConnectionFactory factory = new LettuceConnectionFactory(host, port);
            factory.afterPropertiesSet();
            return factory;
        }

        @Bean
        StringRedisTemplate stringRedisTemplate(RedisConnectionFactory redisConnectionFactory) {
            return new StringRedisTemplate(redisConnectionFactory);
        }

        @Bean
        ObjectMapper objectMapper() {
            return new ObjectMapper().findAndRegisterModules();
        }

        @Bean
        RedisTokenService redisTokenService(
                StringRedisTemplate redisTemplate,
                ObjectMapper objectMapper
        ) {
            return new RedisTokenService(redisTemplate, objectMapper);
        }
    }
}
