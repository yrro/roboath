package roboath.protocol.dynalogin;

import lombok.Getter;

@Getter
enum Message {
    GREETING(220, "Ready"),
    GOODBYE(221, "See ya starside"),
    OK(250, "Authorized"),
    UNAUTHORIZED(401, "Unauthorized"),
    UNKNOWN_COMMAND(500, "Command not recognized"),
    SYNTAX_ERROR(501, "Syntax error in parameter or arguments"),
    NOT_IMPLEMENTED(502, "Command not implemented"),
    TIMEOUT(503, "Timed out waiting for command"),
    TOO_MANY_ERRORS(504, "Too many errors. Goodbye!");

    @Getter
    private int code;

    @Getter
    private String description;

    Message(int code, String description) {
        this.code = code;
        this.description = description;
    }
}
