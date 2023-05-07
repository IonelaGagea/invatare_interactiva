package com.example.demo.security.jwt;

import org.springframework.security.core.AuthenticationException;

public class UserAlreadyExistentException extends AuthenticationException {
    public UserAlreadyExistentException(String msg) {
        super(msg);
    }
}
