package com.github.h3yow.tokengovernancejava.credential;

/**
 * 凭证签发/刷新/鉴权过程中的业务异常，错误类型必须可区分。
 */
public class CredentialException extends RuntimeException {

    private final CredentialErrorType errorType;

    public CredentialException(CredentialErrorType errorType, String message) {
        super(message);
        this.errorType = errorType;
    }

    public CredentialErrorType getErrorType() {
        return errorType;
    }
}
