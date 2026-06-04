package yusufjon.uz.authsessionstore.exception;

import java.time.Instant;

public record ErrorResponse (
        Instant timeStamp,
        int status,
        String error,
        String message,
        String path
) {
}
