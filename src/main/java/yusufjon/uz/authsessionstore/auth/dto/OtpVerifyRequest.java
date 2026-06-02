package yusufjon.uz.authsessionstore.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record OtpVerifyRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Email is invalid")
        String email,

        @NotBlank(message = "OTP is required")
        @Pattern(regexp = "\\d{6}", message = "OTP must contain exactly 6 digits")
        String otp
) {
}
