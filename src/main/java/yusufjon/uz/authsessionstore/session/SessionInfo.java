package yusufjon.uz.authsessionstore.session;

import java.time.Instant;
import java.util.UUID;

public record SessionInfo(
        UUID sessionId,
        Long userId,
        String email,
        String ipAddress,
        String userAgent,
        Instant createdAt,
        Instant expiresAt
) {

}
