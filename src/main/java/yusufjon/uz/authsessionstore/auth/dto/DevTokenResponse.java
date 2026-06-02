package yusufjon.uz.authsessionstore.auth.dto;

public record DevTokenResponse(
        String message,
        String devValue
) {
}

// DevTokenResponse is for development. In Real Production we use email sender or OTP