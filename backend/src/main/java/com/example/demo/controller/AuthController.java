package com.example.demo.controller;

import com.example.demo.dto.UserDto;
import com.example.demo.security.jwt.JwtService;
import com.example.demo.security.jwt.Token;
import com.example.demo.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@Slf4j
@RestController
@RequiredArgsConstructor
public class AuthController {

    private final JwtService jwtService;


    @PostMapping("/login")
    public Token loginUser(String email, String password) {
        return jwtService.getTokensAtLogin(email, password);
    }

    @PostMapping("/register")
    public Token registerUser(@RequestBody UserDto userDto) {
        return jwtService.getTokensAtRegister(userDto);
    }

    @PostMapping("/refresh")
    public Token refreshAccessToken(@RequestBody String refreshToken) {
        return jwtService.getTokensAtRefresh(refreshToken);
    }

    @GetMapping("/profile")
    @PreAuthorize("hasRole('USER')")
    public String profile() {
        return "profile page";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String admin() {
        return "admin page";
    }

}