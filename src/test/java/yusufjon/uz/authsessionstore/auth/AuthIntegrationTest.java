package yusufjon.uz.authsessionstore.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import yusufjon.uz.authsessionstore.redis.RedisTokenService;
import yusufjon.uz.authsessionstore.security.JwtService;
import yusufjon.uz.authsessionstore.session.SessionInfo;
import yusufjon.uz.authsessionstore.user.User;
import yusufjon.uz.authsessionstore.user.UserRepository;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
class AuthIntegrationTest {

    private static final int REDIS_PORT = 6379;
    private static final String JWT_SECRET = Base64.getEncoder().encodeToString(
            "integration-test-jwt-secret-integration-test-jwt-secret-12345"
                    .getBytes(StandardCharsets.UTF_8)
    );

    @Container
    static final PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("auth_session_store_test")
            .withUsername("postgres")
            .withPassword("postgres");

    @Container
    static final GenericContainer<?> redis = new GenericContainer<>("redis:7-alpine")
            .withExposedPorts(REDIS_PORT);

    @DynamicPropertySource
    static void dynamicProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.data.redis.host", redis::getHost);
        registry.add("spring.data.redis.port", () -> redis.getMappedPort(REDIS_PORT));
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
        registry.add("spring.flyway.enabled", () -> true);
        registry.add("spring.flyway.locations", () -> "classpath:db/migration");
        registry.add("management.health.mail.enabled", () -> false);
        registry.add("spring.data.redis.repositories.enabled", () -> false);
        registry.add("app.jwt.secret", () -> JWT_SECRET);
        registry.add("app.jwt.access-token-expiration-minutes", () -> 15);
        registry.add("app.jwt.refresh-token-expiration-days", () -> 7);
        registry.add("app.otp.expiration-minutes", () -> 5);
        registry.add("app.password-reset.expiration-minutes", () -> 15);
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RedisTokenService redisTokenService;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private StringRedisTemplate redisTemplate;

    @BeforeEach
    void setUp() {
        flushRedis();
        userRepository.deleteAllInBatch();
    }

    @Test
    void healthEndpointShouldReturnUp() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }

    @Test
    void registerShouldCreateUser() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of(
                                "fullName", "Integration User",
                                "email", "create@example.com",
                                "password", "Password123"
                        ))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.message").value("User registered successfully"));

        Optional<User> createdUser = userRepository.findByEmail("create@example.com");
        assertThat(createdUser).isPresent();
        assertThat(createdUser.get().getPassword()).isNotEqualTo("Password123");
        assertThat(createdUser.get().getRole().name()).isEqualTo("USER");
    }

    @Test
    void registerDuplicateEmailShouldReturnConflict() throws Exception {
        registerUser("duplicate@example.com", "Password123");

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of(
                                "fullName", "Duplicate User",
                                "email", "duplicate@example.com",
                                "password", "Password123"
                        ))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409))
                .andExpect(jsonPath("$.message").value("Email already exists"));
    }

    @Test
    void loginWithValidCredentialsShouldReturnAccessTokenAndRefreshToken() throws Exception {
        registerUser("login@example.com", "Password123");

        MvcResult result = login("login@example.com", "Password123");

        JsonNode body = body(result);
        assertThat(body.get("accessToken").asText()).isNotBlank();
        assertThat(body.get("refreshToken").asText()).isNotBlank();
        assertThat(body.get("tokenType").asText()).isEqualTo("Bearer");
        assertThat(body.get("expiresInSeconds").asLong()).isPositive();
    }

    @Test
    void loginWithInvalidPasswordShouldReturnUnauthorized() throws Exception {
        registerUser("invalid-password@example.com", "Password123");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of(
                                "email", "invalid-password@example.com",
                                "password", "WrongPassword123"
                        ))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401));
    }

    @Test
    void protectedSessionsEndpointWithoutTokenShouldReturnUnauthorizedOrForbidden() throws Exception {
        mockMvc.perform(get("/api/sessions"))
                .andExpect(result -> assertThat(result.getResponse().getStatus()).isIn(401, 403));
    }

    @Test
    void loginThenSessionsShouldReturnSessionListWithOneSession() throws Exception {
        registerUser("sessions@example.com", "Password123");
        String accessToken = extractAccessToken(login("sessions@example.com", "Password123"));

        mockMvc.perform(get("/api/sessions")
                        .header(AUTHORIZATION, authHeader(accessToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].email").value("sessions@example.com"));
    }

    @Test
    void loginThenRefreshTokenShouldReturnNewAccessToken() throws Exception {
        registerUser("refresh@example.com", "Password123");
        MvcResult loginResult = login("refresh@example.com", "Password123");
        String accessToken = extractAccessToken(loginResult);
        String refreshToken = extractRefreshToken(loginResult);

        MvcResult refreshResult = mockMvc.perform(post("/api/auth/refresh-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("refreshToken", refreshToken))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").value(refreshToken))
                .andReturn();

        assertThat(extractAccessToken(refreshResult)).isNotEqualTo(accessToken);
    }

    @Test
    void loginThenLogoutShouldRemoveSessionRefreshTokenAndBlacklistAccessToken() throws Exception {
        registerUser("logout@example.com", "Password123");
        MvcResult loginResult = login("logout@example.com", "Password123");
        String accessToken = extractAccessToken(loginResult);
        Long userId = jwtService.extractUserId(accessToken);
        UUID sessionId = jwtService.extractSessionId(accessToken);
        String jwtId = jwtService.extractJti(accessToken);

        mockMvc.perform(post("/api/auth/logout")
                        .header(AUTHORIZATION, authHeader(accessToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Logged out successfully"));

        assertThat(redisTokenService.findRefreshToken(userId, sessionId)).isEmpty();
        assertThat(redisTokenService.findSessionsByUserId(userId)).isEmpty();
        assertThat(redisTokenService.isAccessTokenBlackListed(jwtId)).isTrue();
    }

    @Test
    void loginThenLogoutThenUseSameAccessTokenAgainstSessionsShouldFail() throws Exception {
        registerUser("blacklisted@example.com", "Password123");
        String accessToken = extractAccessToken(login("blacklisted@example.com", "Password123"));

        mockMvc.perform(post("/api/auth/logout")
                        .header(AUTHORIZATION, authHeader(accessToken)))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/sessions")
                        .header(AUTHORIZATION, authHeader(accessToken)))
                .andExpect(result -> assertThat(result.getResponse().getStatus()).isIn(401, 403));
    }

    @Test
    void sendOtpShouldReturnDevValue() throws Exception {
        MvcResult result = sendOtp("otp@example.com");

        JsonNode body = body(result);
        assertThat(body.get("message").asText()).contains("OTP generated successfully");
        assertThat(body.get("devValue").asText()).matches("\\d{6}");
    }

    @Test
    void verifyOtpShouldSucceed() throws Exception {
        String otp = extractDevValue(sendOtp("verify-otp@example.com"));

        mockMvc.perform(post("/api/auth/verify-otp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of(
                                "email", "verify-otp@example.com",
                                "otp", otp
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("OTP verified successfully"));
    }

    @Test
    void verifyOtpTwiceShouldFailSecondTime() throws Exception {
        String email = "verify-twice@example.com";
        String otp = extractDevValue(sendOtp(email));

        mockMvc.perform(post("/api/auth/verify-otp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("email", email, "otp", otp))))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/auth/verify-otp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("email", email, "otp", otp))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("OTP expired or not found"));
    }

    @Test
    void forgotPasswordShouldReturnResetToken() throws Exception {
        registerUser("forgot@example.com", "Password123");

        MvcResult result = forgotPassword("forgot@example.com");

        String resetToken = extractDevValue(result);
        assertThat(UUID.fromString(resetToken)).isNotNull();
    }

    @Test
    void resetPasswordShouldUpdatePasswordRevokeSessionsAndAllowNewPasswordLogin() throws Exception {
        String email = "reset@example.com";
        registerUser(email, "Password123");
        String oldAccessToken = extractAccessToken(login(email, "Password123"));
        Long userId = jwtService.extractUserId(oldAccessToken);
        UUID oldSessionId = jwtService.extractSessionId(oldAccessToken);
        String resetToken = extractDevValue(forgotPassword(email));

        mockMvc.perform(post("/api/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of(
                                "token", resetToken,
                                "newPassword", "NewPassword123"
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message")
                        .value("Password reset successfully. All sessions were revoked."));

        assertThat(redisTokenService.findSessionsByUserId(userId)).isEmpty();
        assertThat(redisTokenService.findRefreshToken(userId, oldSessionId)).isEmpty();

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of(
                                "email", email,
                                "password", "Password123"
                        ))))
                .andExpect(status().isUnauthorized());

        login(email, "NewPassword123");
    }

    @Test
    void logoutAllShouldRemoveAllSessionsAndRefreshTokens() throws Exception {
        String email = "logout-all@example.com";
        registerUser(email, "Password123");
        MvcResult firstLogin = login(email, "Password123");
        MvcResult secondLogin = login(email, "Password123");
        String firstAccessToken = extractAccessToken(firstLogin);
        String secondAccessToken = extractAccessToken(secondLogin);
        String firstRefreshToken = extractRefreshToken(firstLogin);
        String secondRefreshToken = extractRefreshToken(secondLogin);
        Long userId = jwtService.extractUserId(firstAccessToken);
        UUID firstSessionId = jwtService.extractSessionId(firstAccessToken);
        UUID secondSessionId = jwtService.extractSessionId(secondAccessToken);

        assertThat(redisTokenService.findRefreshToken(userId, firstSessionId))
                .contains(firstRefreshToken);
        assertThat(redisTokenService.findRefreshToken(userId, secondSessionId))
                .contains(secondRefreshToken);

        mockMvc.perform(delete("/api/sessions/logout-all")
                        .header(AUTHORIZATION, authHeader(firstAccessToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("All sessions deleted successfully"));

        assertThat(redisTokenService.findRefreshToken(userId, firstSessionId)).isEmpty();
        assertThat(redisTokenService.findRefreshToken(userId, secondSessionId)).isEmpty();
        assertThat(redisTokenService.findSessionsByUserId(userId)).isEmpty();
    }

    @Test
    void deleteOneSessionBySessionIdShouldRemoveThatSessionFromRedis() throws Exception {
        String email = "delete-one@example.com";
        registerUser(email, "Password123");
        MvcResult firstLogin = login(email, "Password123");
        MvcResult secondLogin = login(email, "Password123");
        String firstAccessToken = extractAccessToken(firstLogin);
        String firstRefreshToken = extractRefreshToken(firstLogin);
        String secondAccessToken = extractAccessToken(secondLogin);
        Long userId = jwtService.extractUserId(firstAccessToken);
        UUID firstSessionId = jwtService.extractSessionId(firstAccessToken);
        UUID secondSessionId = jwtService.extractSessionId(secondAccessToken);

        mockMvc.perform(delete("/api/sessions/{sessionId}", secondSessionId)
                        .header(AUTHORIZATION, authHeader(firstAccessToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Session deleted successfully"));

        assertThat(redisTokenService.findRefreshToken(userId, secondSessionId)).isEmpty();
        assertThat(redisTokenService.findRefreshToken(userId, firstSessionId))
                .contains(firstRefreshToken);

        List<SessionInfo> sessions = redisTokenService.findSessionsByUserId(userId);
        assertThat(sessions).hasSize(1);
        assertThat(sessions.getFirst().sessionId()).isEqualTo(firstSessionId);
    }

    private MvcResult registerUser(String email, String password) throws Exception {
        return mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of(
                                "fullName", "Integration User",
                                "email", email,
                                "password", password
                        ))))
                .andExpect(status().isCreated())
                .andReturn();
    }

    private MvcResult login(String email, String password) throws Exception {
        return mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of(
                                "email", email,
                                "password", password
                        ))))
                .andExpect(status().isOk())
                .andReturn();
    }

    private MvcResult sendOtp(String email) throws Exception {
        return mockMvc.perform(post("/api/auth/send-otp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("email", email))))
                .andExpect(status().isOk())
                .andReturn();
    }

    private MvcResult forgotPassword(String email) throws Exception {
        return mockMvc.perform(post("/api/auth/forgot-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("email", email))))
                .andExpect(status().isOk())
                .andReturn();
    }

    private String extractAccessToken(MvcResult response) throws Exception {
        return body(response).get("accessToken").asText();
    }

    private String extractRefreshToken(MvcResult response) throws Exception {
        return body(response).get("refreshToken").asText();
    }

    private String extractDevValue(MvcResult response) throws Exception {
        return body(response).get("devValue").asText();
    }

    private String authHeader(String token) {
        return "Bearer " + token;
    }

    private void flushRedis() {
        redisTemplate.execute((RedisCallback<Void>) connection -> {
            connection.serverCommands().flushDb();
            return null;
        });
    }

    private String json(Object value) throws Exception {
        return objectMapper.writeValueAsString(value);
    }

    private JsonNode body(MvcResult response) throws Exception {
        return objectMapper.readTree(response.getResponse().getContentAsString());
    }
}
