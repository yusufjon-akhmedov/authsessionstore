package yusufjon.uz.authsessionstore.auth;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import yusufjon.uz.authsessionstore.auth.dto.*;
import yusufjon.uz.authsessionstore.exception.ApiException;
import yusufjon.uz.authsessionstore.redis.RedisTokenService;
import yusufjon.uz.authsessionstore.security.JwtService;
import yusufjon.uz.authsessionstore.session.SessionInfo;
import yusufjon.uz.authsessionstore.user.Role;
import yusufjon.uz.authsessionstore.user.User;
import yusufjon.uz.authsessionstore.user.UserRepository;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.springframework.http.HttpStatus.*;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RedisTokenService redisTokenService;

    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${app.otp.expiration-minutes}")
    private long otpExpirationMinutes;

    @Value("${app.password-reset.expiration-minutes}")
    private long passwordResetExpirationMinutes;

    @Transactional
    public MessageResponse register(RegisterRequest request) {
        String email = normalizeEmail(request.email());

        if (userRepository.existsByEmail(email)) {
            throw new ApiException(CONFLICT, "Email already exists");
        }

        User user = User.builder()
                .fullName(request.fullName().trim())
                .email(email)
                .password(passwordEncoder.encode(request.password()))
                .role(Role.USER)
                .enabled(true)
                .build();

        userRepository.save(user);

        return new MessageResponse("User registered successfully");
    }

    public TokenResponse login(LoginRequest request, String ipAddress, String userAgent) {
        String email = normalizeEmail(request.email());

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, request.password())
            );
        } catch (BadCredentialsException e) {
            throw new ApiException(UNAUTHORIZED, "Invalid email or password");
        }

        User user = findUserByEmail(email);

        UUID sessionId = UUID.randomUUID();
        Duration refreshTtl = jwtService.getRefreshTokenTtl();

        String accessToken = jwtService.generateAccessToken(user, sessionId);
        String refreshToken = jwtService.generateRefreshToken(user, sessionId);

        redisTokenService.saveRefreshToken(
                user.getId(),
                sessionId,
                refreshToken,
                refreshTtl
        );

        Instant now = Instant.now();

        SessionInfo sessionInfo = new SessionInfo(
                sessionId,
                user.getId(),
                user.getEmail(),
                ipAddress,
                userAgent,
                now,
                now.plus(refreshTtl)
        );

        redisTokenService.saveSession(sessionInfo, refreshTtl);

        return new TokenResponse(
                accessToken,
                refreshToken,
                "Bearer",
                jwtService.getAccessTokenTtl().toSeconds()
        );
    }

    public TokenResponse refreshToken(RefreshTokenRequest request) {
        String refreshToken = request.refreshToken();

        Claims claims = jwtService.parseClaims(refreshToken);

        String tokenType = claims.get("tokenType", String.class);

        if (!"refresh".equals(tokenType)) {
            throw new ApiException(UNAUTHORIZED, "Invalid refresh token");
        }

        String email = claims.getSubject();
        String sessionIdValue = claims.get("sessionId", String.class);

        if (email == null || sessionIdValue == null) {
            throw new ApiException(UNAUTHORIZED, "Invalid refresh token");
        }

        User user = findUserByEmail(email);
        UUID sessionId = UUID.fromString(sessionIdValue);

        String storedRefreshToken = redisTokenService
                .findRefreshToken(user.getId(), sessionId)
                .orElseThrow(() -> new ApiException(
                        UNAUTHORIZED,
                        "Refresh token expired or revoked"
                ));

        if (!storedRefreshToken.equals(refreshToken)) {
            throw new ApiException(UNAUTHORIZED, "Refresh token mismatch");
        }

        String newAccessToken = jwtService.generateAccessToken(user, sessionId);

        return new TokenResponse(
                newAccessToken,
                refreshToken,
                "Bearer",
                jwtService.getAccessTokenTtl().toSeconds()
        );
    }

    public MessageResponse logout(String accessToken) {
        Claims claims = jwtService.parseClaims(accessToken);

        String tokenType = claims.get("tokenType", String.class);

        if (!"access".equals(tokenType)) {
            throw new ApiException(UNAUTHORIZED, "Invalid access token");
        }

        Number userIdNumber = claims.get("userId", Number.class);
        String sessionIdValue = claims.get("sessionId", String.class);
        String jwtId = claims.getId();

        if (userIdNumber == null || sessionIdValue == null || jwtId == null) {
            throw new ApiException(UNAUTHORIZED, "Invalid access token");
        }

        Long userId = userIdNumber.longValue();
        UUID sessionId = UUID.fromString(sessionIdValue);

        Duration remainingTtl = jwtService.getRemainingTtl(claims);

        redisTokenService.deleteSession(userId, sessionId);
        redisTokenService.blackListAccessToken(jwtId, remainingTtl);

        return new MessageResponse("Logged out successfully");
    }

    public DevTokenResponse sendOtp(OtpSendRequest request) {
        String email = normalizeEmail(request.email());

        String otp = generateOtp();
        Duration ttl = Duration.ofMinutes(otpExpirationMinutes);

        redisTokenService.saveOtp(email, otp, ttl);

        return new DevTokenResponse(
                "OTP generated successfully. Development mode: OTP is returned in response.",
                otp
        );
    }

    public MessageResponse verifyOtp(OtpVerifyRequest request) {
        String email = normalizeEmail(request.email());

        String storedOtp = redisTokenService.findOtp(email)
                .orElseThrow(() -> new ApiException(
                        BAD_REQUEST,
                        "OTP expired or not found"
                ));

        if (!storedOtp.equals(request.otp())) {
            throw new ApiException(BAD_REQUEST, "Invalid OTP");
        }

        redisTokenService.deleteOtp(email);

        return new MessageResponse("OTP verified successfully");
    }

    public DevTokenResponse forgotPassword(ForgotPasswordRequest request) {
        String email = normalizeEmail(request.email());

        User user = findUserByEmail(email);

        String resetToken = UUID.randomUUID().toString();
        Duration ttl = Duration.ofMinutes(passwordResetExpirationMinutes);

        redisTokenService.savePasswordResetToken(resetToken, user.getId(), ttl);

        return new DevTokenResponse(
                "Password reset token generated successfully. Development mode: token is returned in response.",
                resetToken
        );
    }

    @Transactional
    public MessageResponse resetPassword(ResetPasswordRequest request) {
        Long userId = redisTokenService.findPasswordResetUserId(request.token())
                .orElseThrow(() -> new ApiException(
                        BAD_REQUEST,
                        "Reset token expired or invalid"
                ));

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ApiException(NOT_FOUND, "User not found"));

        user.setPassword(passwordEncoder.encode(request.newPassword()));
        userRepository.save(user);

        redisTokenService.deletePasswordResetToken(request.token());
        redisTokenService.deleteAllSessions(user.getId());

        return new MessageResponse("Password reset successfully. All sessions were revoked.");
    }

    private User findUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new ApiException(NOT_FOUND, "User not found"));
    }

    private String generateOtp() {
        int number = secureRandom.nextInt(1_000_000);
        return String.format("%06d", number);
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase();
    }
}