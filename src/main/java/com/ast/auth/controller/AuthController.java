package com.ast.auth.controller;

import com.ast.auth.model.User;
import com.ast.auth.security.JwtUtil;
import com.ast.auth.service.UserService;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@AllArgsConstructor
public class AuthController {

    private final UserService userService;
    private final JwtUtil jwtUtil;

    record RegisterRequest(String username, String password) {}
    record LoginRequest(String username, String password) {}

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody @Valid RegisterRequest registerRequest) {
        try {
            User u = userService.register(registerRequest.username(), registerRequest.password());
            return ResponseEntity.ok(Map.of("id", u.getId(), "username", u.getUsername()));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().body(Map.of("error", ex.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody @Valid LoginRequest loginRequest) {
        User u = userService.findByUsername(loginRequest.username());
        if (u == null) return ResponseEntity.status(401).body(Map.of("error", "invalid credentials"));

        // password check
        org.springframework.security.crypto.password.PasswordEncoder enc = new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder();
        if (!enc.matches(loginRequest.password(), u.getPassword())) {
            return ResponseEntity.status(401).body(Map.of("error", "invalid credentials"));
        }

        String token = jwtUtil.generateToken(u.getUsername());
        return ResponseEntity.ok(Map.of("token", token));
    }
}