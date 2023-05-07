package com.example.demo.security.jwt;

import com.example.demo.dto.UserDto;
import com.example.demo.entitiy.User;
import com.example.demo.service.UserService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.sql.Date;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class JwtService {

    private final Key key;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    @Value("${jwt.accessTokenExpiration}")
    private int accessTokenExpiration;

    @Value("${jwt.refreshTokenExpiration}")
    private int refreshTokenExpiration;

    public JwtService(@Value("${jwt.secret}") String secret, UserService userService,
                      PasswordEncoder passwordEncoder) {
        key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    public String createToken(String sub, Map<String, Object> claims, Integer millisToExpire) {
        return Jwts.builder()
                .setSubject(sub)
                .addClaims(claims)
                .setExpiration(Date.from(Instant.now().plus(millisToExpire, ChronoUnit.MILLIS)))
                .signWith(key)
                .compact();
    }

    public Map<String, Object> parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public Token getTokensAtLogin(String email, String password) {
        User user = userService.findUserByEmail(email);

        if (passwordEncoder.matches(password, user.getPassword())) {
            String rolesString = convertAuthoritiesListToString(user);
            Token tokens = new Token();
            tokens.setAccessToken(createToken(user.getEmail(), Map.of("roles", rolesString),
                    accessTokenExpiration));
            tokens.setRefreshToken(createToken(user.getEmail(), Map.of("roles", rolesString),
                    refreshTokenExpiration));
            return tokens;
        } else {
            throw new IncorrectPasswordException("Incorrect password");
        }
    }

    public Token getTokensAtRegister(UserDto userDto) {
        User user = userService.findUserByEmail(userDto.getEmail());
        if (user != null) {
            throw new UserAlreadyExistentException("User with email " + userDto.getEmail() + " already existent");
        }
        userService.saveUser(userDto);
        String rolesString = convertAuthoritiesListToString(user);
        Token tokens = new Token();
        tokens.setAccessToken(createToken(user.getEmail(), Map.of("roles", rolesString),
                accessTokenExpiration));
        tokens.setRefreshToken(createToken(user.getEmail(), Map.of("roles", rolesString),
                refreshTokenExpiration));
        return tokens;
    }

    public Token getTokensAtRefresh(String refreshToken) {
        Map<String, Object> claims;
        try {
            claims = parseClaims(refreshToken);
            String email = (String) claims.get("sub");
            User user = userService.findUserByEmail(email);
            String rolesString = convertAuthoritiesListToString(user);
            Token newTokens = new Token();
            newTokens.setAccessToken(
                    createToken(user.getEmail(), Map.of("roles", rolesString),
                            accessTokenExpiration));
            newTokens.setRefreshToken(refreshToken);
            return newTokens;
        } catch (ExpiredJwtException ex) {
            throw new RefreshTokenExpiredException("Expired refresh token");
        }
    }

    private String convertAuthoritiesListToString(User user) {
        return user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
    }
}

