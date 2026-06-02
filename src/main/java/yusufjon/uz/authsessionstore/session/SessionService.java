package yusufjon.uz.authsessionstore.session;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import yusufjon.uz.authsessionstore.exception.ApiException;
import yusufjon.uz.authsessionstore.redis.RedisTokenService;
import yusufjon.uz.authsessionstore.user.User;
import yusufjon.uz.authsessionstore.user.UserRepository;

import java.util.List;
import java.util.UUID;

import static org.springframework.http.HttpStatus.NOT_FOUND;

@Service
@RequiredArgsConstructor
public class SessionService {

    private final UserRepository userRepository;
    private final RedisTokenService redisTokenService;

    public List<SessionInfo> getMySessions(String email) {
        User user = findUserByEmail(email);
        return redisTokenService.findSessionsByUserId(user.getId());
    }

    public void deleteMySessions(String email, UUID sessionId) {
        User user = findUserByEmail(email);
        redisTokenService.deleteSession(user.getId(), sessionId);
    }

    public void deleteAllMySessions(String email) {
        User user = findUserByEmail(email);
        redisTokenService.deleteAllSessions(user.getId());
    }

    private User findUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new ApiException(NOT_FOUND, "User not found"));
    }
}
