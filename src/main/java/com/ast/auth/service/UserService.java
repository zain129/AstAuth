package com.ast.auth.service;

import com.ast.auth.model.Role;
import com.ast.auth.model.User;
import com.ast.auth.repository.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@AllArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * Register a new user with a role.
     *
     * @param username    username
     * @param rawPassword raw password
     * @param role        string role (USER, ADMIN)
     * @return saved User
     */
    public User registerUser(String username, String rawPassword, String role) {
        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("Username already exists");
        }

        Role assignedRole;
        try {
            assignedRole = Role.valueOf(role.toUpperCase());
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid role");
        }

        User user = User.builder()
                .username(username)
                .password(passwordEncoder.encode(rawPassword))
                .role(assignedRole)
                .build();

        return userRepository.save(user);
    }

    /**
     * Find a user by username.
     */
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }
}
