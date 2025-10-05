package com.ast.auth.controller;

import com.ast.auth.model.User;
import com.ast.auth.service.JwtService;
import com.ast.auth.service.UserService;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@AllArgsConstructor
public class AuthController {

    private final AuthenticationManager authManager;
    private final UserService userService;
    private final JwtService jwtService;
    private final org.springframework.security.core.userdetails.UserDetailsService userDetailsService;

    public record RegisterRequest(String username, String password, String role) {}
    public record LoginRequest(String username, String password) {}

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest registerRequest) {
        try {
            User user = userService.registerUser(registerRequest.username(), registerRequest.password(), registerRequest.role());
            return ResponseEntity
                    .status(201)
                    .body(Map.of("id", user.getId(), "username", user.getUsername(), "role", user.getRole()));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity
                    .status(400)
                    .body(Map.of("error", ex.getMessage()));
        } catch (Exception ex) {
            return ResponseEntity
                    .status(500)
                    .body(Map.of("error", "Internal server error"));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        try {
            authManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.username(), loginRequest.password()));
            UserDetails userDetails = userDetailsService.loadUserByUsername(loginRequest.username());
            String token = jwtService.generateToken(userDetails);
            Long expiration = jwtService.extractExpiration(token);

            return ResponseEntity.ok(Map.of(
                    "accessToken", token,
                    "tokenType", "Bearer",
                    "expiration", expiration
            ));
        } catch (BadCredentialsException ex) {
            return ResponseEntity
                    .status(401)
                    .body(Map.of("error", "Invalid username or password"));
        } catch (Exception ex) {
            return ResponseEntity
                    .status(500)
                    .body(Map.of("error", "Internal server error"));
        }
    }
}
