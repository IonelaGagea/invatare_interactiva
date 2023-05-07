package com.example.demo.security.jwt;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@Setter
@Getter
public class Token {

    private String accessToken;
    private String refreshToken;
}
