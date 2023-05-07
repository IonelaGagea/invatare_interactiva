package com.example.demo.security.jwt;

import org.springframework.security.core.AuthenticationException;

public class RefreshTokenExpiredException extends AuthenticationException {
    public RefreshTokenExpiredException(String e) {
        super(e);
    }
}
