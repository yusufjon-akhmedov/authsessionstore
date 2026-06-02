package yusufjon.uz.authsessionstore.session;


import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import yusufjon.uz.authsessionstore.auth.dto.MessageResponse;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/sessions")
@RequiredArgsConstructor
public class SessionController {

    private final SessionService sessionService;

    @GetMapping
    public List<SessionInfo> getMySessions(Authentication authentication) {
        return sessionService.getMySessions(authentication.getName());
    }

    @DeleteMapping("/{sessionId}")
    public MessageResponse deleteSession(
            Authentication authentication,
            @PathVariable UUID sessionId
    ) {
        sessionService.deleteMySessions(authentication.getName(), sessionId);
        return new MessageResponse("Session deleted successfully");
    }

    @DeleteMapping("/logout-all")
    public MessageResponse logoutAll(Authentication authentication) {
        sessionService.deleteAllMySessions(authentication.getName());
        return new MessageResponse("All sessions deleted successfully");
    }
}
