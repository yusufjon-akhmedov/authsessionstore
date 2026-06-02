package yusufjon.uz.authsessionstore.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record OtpSendRequest (
        @NotBlank(message = "Email is required")
        @Email(message = "Email is invalid")
        String email
) {
}
