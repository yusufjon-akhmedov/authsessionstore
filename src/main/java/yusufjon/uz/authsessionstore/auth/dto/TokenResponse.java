package yusufjon.uz.authsessionstore.auth.dto;

public record TokenResponse (
        String accessToken,
        String refreshToken,
        String tokenType,
        long expiresInSeconds
) {
}
