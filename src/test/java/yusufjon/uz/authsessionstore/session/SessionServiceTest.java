package yusufjon.uz.authsessionstore.session;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import yusufjon.uz.authsessionstore.exception.ApiException;
import yusufjon.uz.authsessionstore.redis.RedisTokenService;
import yusufjon.uz.authsessionstore.user.Role;
import yusufjon.uz.authsessionstore.user.User;
import yusufjon.uz.authsessionstore.user.UserRepository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SessionServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RedisTokenService redisTokenService;

    @InjectMocks
    private SessionService sessionService;

    @Test
    void getMySessionsShouldReturnSessionsFromRedisForAuthenticatedUser() {
        User user = user(1L, "user@example.com");
        SessionInfo session = sessionInfo(1L, "user@example.com", UUID.randomUUID());

        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(redisTokenService.findSessionsByUserId(1L)).thenReturn(List.of(session));

        List<SessionInfo> result = sessionService.getMySessions("user@example.com");

        assertThat(result).containsExactly(session);
        verify(redisTokenService).findSessionsByUserId(1L);
    }

    @Test
    void getMySessionsShouldThrowNotFoundIfUserDoesNotExist() {
        when(userRepository.findByEmail("missing@example.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> sessionService.getMySessions("missing@example.com"))
                .isInstanceOfSatisfying(ApiException.class, exception -> {
                    assertThat(exception.getStatus()).isEqualTo(HttpStatus.NOT_FOUND);
                    assertThat(exception.getMessage()).isEqualTo("User not found");
                });

        verify(redisTokenService, never()).findSessionsByUserId(any());
    }

    @Test
    void deleteMySessionShouldDeleteOnlyRequestedSession() {
        User user = user(1L, "user@example.com");
        UUID sessionId = UUID.randomUUID();

        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));

        sessionService.deleteMySessions("user@example.com", sessionId);

        verify(redisTokenService).deleteSession(1L, sessionId);
        verify(redisTokenService, never()).deleteAllSessions(any());
    }

    @Test
    void deleteAllMySessionsShouldDeleteAllSessionsForUser() {
        User user = user(1L, "user@example.com");

        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));

        sessionService.deleteAllMySessions("user@example.com");

        verify(redisTokenService).deleteAllSessions(1L);
        verify(redisTokenService, never()).deleteSession(any(), any());
    }

    private User user(Long id, String email) {
        return User.builder()
                .id(id)
                .fullName("Test User")
                .email(email)
                .password("encoded-password")
                .role(Role.USER)
                .enabled(true)
                .build();
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
}
