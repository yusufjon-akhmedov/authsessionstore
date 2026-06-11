package yusufjon.uz.authsessionstore.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import yusufjon.uz.authsessionstore.auth.dto.*;
import yusufjon.uz.authsessionstore.exception.ApiException;
import yusufjon.uz.authsessionstore.redis.RedisTokenService;
import yusufjon.uz.authsessionstore.security.JwtService;
import yusufjon.uz.authsessionstore.session.SessionInfo;
import yusufjon.uz.authsessionstore.user.Role;
import yusufjon.uz.authsessionstore.user.User;
import yusufjon.uz.authsessionstore.user.UserRepository;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private JwtService jwtService;

    @Mock
    private RedisTokenService redisTokenService;

    @InjectMocks
    private AuthService authService;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(authService, "otpExpirationMinutes", 5L);
        ReflectionTestUtils.setField(authService, "passwordResetExpirationMinutes", 15L);
    }

    @Test
    void registerShouldCreateUserSuccessfully() {
        RegisterRequest request = new RegisterRequest(
                "  Test User  ",
                "  USER@Example.COM  ",
                "password123"
        );

        when(userRepository.existsByEmail("user@example.com")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("encoded-password");

        MessageResponse response = authService.register(request);

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());

        User savedUser = userCaptor.getValue();
        assertThat(response.message()).isEqualTo("User registered successfully");
        assertThat(savedUser.getFullName()).isEqualTo("Test User");
        assertThat(savedUser.getEmail()).isEqualTo("user@example.com");
        assertThat(savedUser.getPassword()).isEqualTo("encoded-password");
        assertThat(savedUser.getRole()).isEqualTo(Role.USER);
        assertThat(savedUser.isEnabled()).isTrue();
    }

    @Test
    void registerShouldThrowConflictWhenEmailAlreadyExists() {
        RegisterRequest request = new RegisterRequest(
                "Test User",
                "user@example.com",
                "password123"
        );

        when(userRepository.existsByEmail("user@example.com")).thenReturn(true);

        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOfSatisfying(ApiException.class, exception -> {
                    assertThat(exception.getStatus()).isEqualTo(HttpStatus.CONFLICT);
                    assertThat(exception.getMessage()).isEqualTo("Email already exists");
                });

        verify(userRepository, never()).save(any());
        verify(passwordEncoder, never()).encode(any());
    }

    @Test
    void loginShouldAuthenticateGenerateTokensSaveRedisStateAndReturnTokenResponse() {
        User user = user(1L, "user@example.com", Role.USER);
        Duration refreshTtl = Duration.ofDays(7);

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(mock(Authentication.class));
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(jwtService.getRefreshTokenTtl()).thenReturn(refreshTtl);
        when(jwtService.generateAccessToken(eq(user), any(UUID.class))).thenReturn("access-token");
        when(jwtService.generateRefreshToken(eq(user), any(UUID.class))).thenReturn("refresh-token");
        when(jwtService.getAccessTokenTtl()).thenReturn(Duration.ofMinutes(15));

        TokenResponse response = authService.login(
                new LoginRequest(" USER@example.com ", "password123"),
                "127.0.0.1",
                "JUnit"
        );

        ArgumentCaptor<UsernamePasswordAuthenticationToken> authenticationCaptor =
                ArgumentCaptor.forClass(UsernamePasswordAuthenticationToken.class);
        ArgumentCaptor<UUID> sessionIdCaptor = ArgumentCaptor.forClass(UUID.class);
        ArgumentCaptor<SessionInfo> sessionInfoCaptor = ArgumentCaptor.forClass(SessionInfo.class);

        verify(authenticationManager).authenticate(authenticationCaptor.capture());
        verify(redisTokenService).saveRefreshToken(
                eq(1L),
                sessionIdCaptor.capture(),
                eq("refresh-token"),
                eq(refreshTtl)
        );
        verify(redisTokenService).saveSession(sessionInfoCaptor.capture(), eq(refreshTtl));

        UsernamePasswordAuthenticationToken authentication = authenticationCaptor.getValue();
        UUID sessionId = sessionIdCaptor.getValue();
        SessionInfo sessionInfo = sessionInfoCaptor.getValue();

        assertThat(authentication.getPrincipal()).isEqualTo("user@example.com");
        assertThat(authentication.getCredentials()).isEqualTo("password123");
        assertThat(sessionInfo.sessionId()).isEqualTo(sessionId);
        assertThat(sessionInfo.userId()).isEqualTo(1L);
        assertThat(sessionInfo.email()).isEqualTo("user@example.com");
        assertThat(sessionInfo.ipAddress()).isEqualTo("127.0.0.1");
        assertThat(sessionInfo.userAgent()).isEqualTo("JUnit");
        assertThat(sessionInfo.expiresAt()).isAfter(sessionInfo.createdAt());
        assertThat(response.accessToken()).isEqualTo("access-token");
        assertThat(response.refreshToken()).isEqualTo("refresh-token");
        assertThat(response.tokenType()).isEqualTo("Bearer");
        assertThat(response.expiresInSeconds()).isEqualTo(900);
    }

    @Test
    void loginShouldThrowUnauthorizedForInvalidCredentials() {
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("bad credentials"));

        assertThatThrownBy(() -> authService.login(
                new LoginRequest("user@example.com", "wrong-password"),
                "127.0.0.1",
                "JUnit"
        )).isInstanceOfSatisfying(ApiException.class, exception -> {
            assertThat(exception.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED);
            assertThat(exception.getMessage()).isEqualTo("Invalid email or password");
        });

        verify(userRepository, never()).findByEmail(any());
        verify(redisTokenService, never()).saveRefreshToken(any(), any(), any(), any());
        verify(redisTokenService, never()).saveSession(any(), any());
    }

    @Test
    void refreshTokenShouldReturnNewAccessTokenWhenRefreshTokenIsValidAndStoredInRedis() {
        UUID sessionId = UUID.randomUUID();
        String refreshToken = "refresh-token";
        User user = user(1L, "user@example.com", Role.USER);

        when(jwtService.parseClaims(refreshToken))
                .thenReturn(claims("user@example.com", 1L, sessionId, "refresh", "refresh-jti"));
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(redisTokenService.findRefreshToken(1L, sessionId)).thenReturn(Optional.of(refreshToken));
        when(jwtService.generateAccessToken(user, sessionId)).thenReturn("new-access-token");
        when(jwtService.getAccessTokenTtl()).thenReturn(Duration.ofMinutes(15));

        TokenResponse response = authService.refreshToken(new RefreshTokenRequest(refreshToken));

        assertThat(response.accessToken()).isEqualTo("new-access-token");
        assertThat(response.refreshToken()).isEqualTo(refreshToken);
        assertThat(response.tokenType()).isEqualTo("Bearer");
        assertThat(response.expiresInSeconds()).isEqualTo(900);
        verify(redisTokenService).findRefreshToken(1L, sessionId);
    }

    @Test
    void refreshTokenShouldThrowUnauthorizedIfTokenTypeIsNotRefresh() {
        UUID sessionId = UUID.randomUUID();
        when(jwtService.parseClaims("access-token"))
                .thenReturn(claims("user@example.com", 1L, sessionId, "access", "access-jti"));

        assertThatThrownBy(() -> authService.refreshToken(new RefreshTokenRequest("access-token")))
                .isInstanceOfSatisfying(ApiException.class, exception -> {
                    assertThat(exception.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED);
                    assertThat(exception.getMessage()).isEqualTo("Invalid refresh token");
                });

        verify(userRepository, never()).findByEmail(any());
        verify(redisTokenService, never()).findRefreshToken(any(), any());
    }

    @Test
    void refreshTokenShouldThrowUnauthorizedIfRedisRefreshTokenIsMissing() {
        UUID sessionId = UUID.randomUUID();
        String refreshToken = "refresh-token";

        when(jwtService.parseClaims(refreshToken))
                .thenReturn(claims("user@example.com", 1L, sessionId, "refresh", "refresh-jti"));
        when(userRepository.findByEmail("user@example.com"))
                .thenReturn(Optional.of(user(1L, "user@example.com", Role.USER)));
        when(redisTokenService.findRefreshToken(1L, sessionId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.refreshToken(new RefreshTokenRequest(refreshToken)))
                .isInstanceOfSatisfying(ApiException.class, exception -> {
                    assertThat(exception.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED);
                    assertThat(exception.getMessage()).isEqualTo("Refresh token expired or revoked");
                });

        verify(jwtService, never()).generateAccessToken(any(), any());
    }

    @Test
    void refreshTokenShouldThrowUnauthorizedIfRefreshTokenMismatch() {
        UUID sessionId = UUID.randomUUID();
        String refreshToken = "refresh-token";

        when(jwtService.parseClaims(refreshToken))
                .thenReturn(claims("user@example.com", 1L, sessionId, "refresh", "refresh-jti"));
        when(userRepository.findByEmail("user@example.com"))
                .thenReturn(Optional.of(user(1L, "user@example.com", Role.USER)));
        when(redisTokenService.findRefreshToken(1L, sessionId)).thenReturn(Optional.of("other-token"));

        assertThatThrownBy(() -> authService.refreshToken(new RefreshTokenRequest(refreshToken)))
                .isInstanceOfSatisfying(ApiException.class, exception -> {
                    assertThat(exception.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED);
                    assertThat(exception.getMessage()).isEqualTo("Refresh token mismatch");
                });

        verify(jwtService, never()).generateAccessToken(any(), any());
    }

    @Test
    void logoutShouldDeleteSessionBlacklistAccessTokenAndReturnSuccessResponse() {
        UUID sessionId = UUID.randomUUID();
        Claims claims = claims("user@example.com", 1L, sessionId, "access", "access-jti");
        Duration remainingTtl = Duration.ofMinutes(10);

        when(jwtService.parseClaims("access-token")).thenReturn(claims);
        when(jwtService.getRemainingTtl(claims)).thenReturn(remainingTtl);

        MessageResponse response = authService.logout("access-token");

        assertThat(response.message()).isEqualTo("Logged out successfully");
        verify(redisTokenService).deleteSession(1L, sessionId);
        verify(redisTokenService).blackListAccessToken("access-jti", remainingTtl);
    }

    @Test
    void sendOtpShouldSaveOtpToRedisAndReturnDevOtpResponse() {
        DevTokenResponse response = authService.sendOtp(new OtpSendRequest(" USER@example.com "));

        ArgumentCaptor<String> otpCaptor = ArgumentCaptor.forClass(String.class);
        verify(redisTokenService).saveOtp(
                eq("user@example.com"),
                otpCaptor.capture(),
                eq(Duration.ofMinutes(5))
        );

        assertThat(otpCaptor.getValue()).matches("\\d{6}");
        assertThat(response.devValue()).isEqualTo(otpCaptor.getValue());
        assertThat(response.message()).contains("OTP generated successfully");
    }

    @Test
    void verifyOtpShouldSucceedWhenOtpMatchesAndDeleteOtp() {
        when(redisTokenService.findOtp("user@example.com")).thenReturn(Optional.of("123456"));

        MessageResponse response = authService.verifyOtp(
                new OtpVerifyRequest(" USER@example.com ", "123456")
        );

        assertThat(response.message()).isEqualTo("OTP verified successfully");
        verify(redisTokenService).deleteOtp("user@example.com");
    }

    @Test
    void verifyOtpShouldFailWhenOtpIsMissing() {
        when(redisTokenService.findOtp("user@example.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.verifyOtp(
                new OtpVerifyRequest("user@example.com", "123456")
        )).isInstanceOfSatisfying(ApiException.class, exception -> {
            assertThat(exception.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(exception.getMessage()).isEqualTo("OTP expired or not found");
        });

        verify(redisTokenService, never()).deleteOtp(any());
    }

    @Test
    void verifyOtpShouldFailWhenOtpDoesNotMatch() {
        when(redisTokenService.findOtp("user@example.com")).thenReturn(Optional.of("654321"));

        assertThatThrownBy(() -> authService.verifyOtp(
                new OtpVerifyRequest("user@example.com", "123456")
        )).isInstanceOfSatisfying(ApiException.class, exception -> {
            assertThat(exception.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(exception.getMessage()).isEqualTo("Invalid OTP");
        });

        verify(redisTokenService, never()).deleteOtp(any());
    }

    @Test
    void forgotPasswordShouldSavePasswordResetTokenInRedisAndReturnDevTokenResponse() {
        User user = user(1L, "user@example.com", Role.USER);
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));

        DevTokenResponse response = authService.forgotPassword(
                new ForgotPasswordRequest(" USER@example.com ")
        );

        ArgumentCaptor<String> tokenCaptor = ArgumentCaptor.forClass(String.class);
        verify(redisTokenService).savePasswordResetToken(
                tokenCaptor.capture(),
                eq(1L),
                eq(Duration.ofMinutes(15))
        );

        assertThat(response.message()).contains("Password reset token generated successfully");
        assertThat(response.devValue()).isEqualTo(tokenCaptor.getValue());
        assertThat(UUID.fromString(response.devValue())).isNotNull();
    }

    @Test
    void resetPasswordShouldUpdatePasswordDeleteResetTokenRevokeSessionsAndReturnSuccessResponse() {
        User user = user(1L, "user@example.com", Role.USER);

        when(redisTokenService.findPasswordResetUserId("reset-token")).thenReturn(Optional.of(1L));
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(passwordEncoder.encode("newPassword123")).thenReturn("new-encoded-password");

        MessageResponse response = authService.resetPassword(
                new ResetPasswordRequest("reset-token", "newPassword123")
        );

        assertThat(response.message())
                .isEqualTo("Password reset successfully. All sessions were revoked.");
        assertThat(user.getPassword()).isEqualTo("new-encoded-password");
        verify(userRepository).save(user);
        verify(redisTokenService).deletePasswordResetToken("reset-token");
        verify(redisTokenService).deleteAllSessions(1L);
    }

    @Test
    void resetPasswordShouldFailWhenResetTokenIsInvalid() {
        when(redisTokenService.findPasswordResetUserId("invalid-token")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.resetPassword(
                new ResetPasswordRequest("invalid-token", "newPassword123")
        )).isInstanceOfSatisfying(ApiException.class, exception -> {
            assertThat(exception.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(exception.getMessage()).isEqualTo("Reset token expired or invalid");
        });

        verify(userRepository, never()).findById(any());
        verify(passwordEncoder, never()).encode(any());
        verify(redisTokenService, never()).deleteAllSessions(any());
    }

    private User user(Long id, String email, Role role) {
        return User.builder()
                .id(id)
                .fullName("Test User")
                .email(email)
                .password("encoded-password")
                .role(role)
                .enabled(true)
                .build();
    }

    private Claims claims(String subject, Long userId, UUID sessionId, String tokenType, String jwtId) {
        return Jwts.claims()
                .subject(subject)
                .id(jwtId)
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusSeconds(900)))
                .add("userId", userId)
                .add("sessionId", sessionId.toString())
                .add("tokenType", tokenType)
                .build();
    }
}
