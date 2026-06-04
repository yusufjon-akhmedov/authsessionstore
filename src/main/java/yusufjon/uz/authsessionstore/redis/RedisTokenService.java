package yusufjon.uz.authsessionstore.redis;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import yusufjon.uz.authsessionstore.exception.ApiException;
import yusufjon.uz.authsessionstore.session.SessionInfo;

import java.time.Duration;
import java.util.*;

import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;

@Service
@RequiredArgsConstructor
public class RedisTokenService {

    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    public void saveRefreshToken(Long userId, UUID sessionId, String refreshToken, Duration ttl) {
        redisTemplate.opsForValue().set(refreshTokenKey(userId, sessionId), refreshToken, ttl);
    }

    public Optional<String> findRefreshToken(Long userId, UUID sessionId) {
        return Optional.ofNullable(redisTemplate.opsForValue().get(refreshTokenKey(userId, sessionId)));
    }

    public void saveSession(SessionInfo sessionInfo, Duration ttl) {
        try {
            String json = objectMapper.writeValueAsString(sessionInfo);

            redisTemplate.opsForValue().set(
                    sessionKey(sessionInfo.userId(), sessionInfo.sessionId()),
                    json,
                    ttl
            );
        } catch (JsonProcessingException e) {
            throw new ApiException(INTERNAL_SERVER_ERROR, "Could not serialize session info");
        }
    }

    public List<SessionInfo> findSessionsByUserId(Long userId) {
        Set<String> keys = redisTemplate.keys(sessionPattern(userId));

        if (keys == null || keys.isEmpty()) {
            return List.of();
        }

        List<SessionInfo> sessions = new ArrayList<>();

        for (String key : keys) {
            String json = redisTemplate.opsForValue().get(key);

            if (json == null) {
                continue;
            }

            try {
                sessions.add(objectMapper.readValue(json, SessionInfo.class));
            } catch (JsonProcessingException e) {
                throw new ApiException(INTERNAL_SERVER_ERROR, "Could not deserialize session info");
            }
        }

        sessions.sort(Comparator.comparing(SessionInfo::createdAt).reversed());
        return sessions;
    }

    public void deleteSession(Long userId, UUID sessionId) {
        redisTemplate.delete(sessionKey(userId, sessionId));
        redisTemplate.delete(refreshTokenKey(userId, sessionId));
    }

    public void deleteAllSessions(Long userId) {
        deleteByPattern(sessionPattern(userId));
        deleteByPattern(refreshTokenPattern(userId));
    }

    public void blackListAccessToken(String jwtId, Duration ttl) {
        if (ttl.isNegative() || ttl.isZero()) {
            return;
        }

        redisTemplate.opsForValue().set(blackListKey(jwtId), "blacklisted", ttl);
    }

    public boolean isAccessTokenBlackListed(String jwtId) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(blackListKey(jwtId)));
    }

    public void saveOtp(String email, String otp, Duration ttl) {
        redisTemplate.opsForValue().set(otpKey(email), otp, ttl);
    }

    public Optional<String> findOtp(String email) {
        return Optional.ofNullable(redisTemplate.opsForValue().get(otpKey(email)));
    }

    public void deleteOtp(String email) {
        redisTemplate.delete(otpKey(email));
    }

    public void savePasswordResetToken(String token, Long userId, Duration ttl) {
        redisTemplate.opsForValue().set(passwordResetKey(token), String.valueOf(userId), ttl);
    }

    public Optional<Long> findPasswordResetUserId(String token) {
        String value = redisTemplate.opsForValue().get(passwordResetKey(token));

        if (value == null) {
            return Optional.empty();
        }

        return Optional.of(Long.valueOf(value));
    }

    public void deletePasswordResetToken(String token) {
        redisTemplate.delete(passwordResetKey(token));
    }

    private void deleteByPattern(String pattern) {
        Set<String> keys = redisTemplate.keys(pattern);

        if (keys != null && !keys.isEmpty()) {
            redisTemplate.delete(keys);
        }
    }

    private String refreshTokenKey(Long userId, UUID sessionId) {
        return "refresh:user:%s:%s".formatted(userId, sessionId);
    }

    private String refreshTokenPattern(Long userId) {
        return "refresh:user:%s:*".formatted(userId);
    }

    private String sessionKey(Long userId, UUID sessionId) {
        return "session:user:%s:%s".formatted(userId, sessionId);
    }

    private String sessionPattern(Long userId) {
        return "session:user:%s:*".formatted(userId);
    }

    private String blackListKey(String jwtId) {
        return "blacklist:access:%s".formatted(jwtId);
    }

    private String otpKey(String email) {
        return "otp:email:%s".formatted(email.toLowerCase());
    }

    private String passwordResetKey(String token) {
        return "password-reset:%s".formatted(token);
    }
}
