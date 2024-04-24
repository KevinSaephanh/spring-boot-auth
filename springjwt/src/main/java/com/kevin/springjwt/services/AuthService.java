package com.kevin.springjwt.services;

import com.kevin.springjwt.dtos.requests.SignUpRequest;
import com.kevin.springjwt.dtos.requests.SigninRequest;
import com.kevin.springjwt.dtos.responses.JwtAuthResponse;
import com.kevin.springjwt.models.Role;
import com.kevin.springjwt.models.User;
import com.kevin.springjwt.repositories.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;

@Slf4j
@Service
public class AuthService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;

    public JwtAuthResponse signup(SignUpRequest req) {
        log.info("AuthService signup: request: {}", req);
        User user = User.builder()
                .email(req.getEmail())
                .username(req.getUsername())
                .password(passwordEncoder.encode(req.getPassword()))
                .role(Role.BASIC)
                .build();
        user = userRepository.save(user);
        log.info("AuthService signup: user saved with id: {}", user.getId());
        String jwt = jwtService.generateToken(new HashMap<>(), user);
        return JwtAuthResponse.builder().token(jwt).build();
    }

    public JwtAuthResponse signin(SigninRequest req) {
        log.info("AuthService signin: request: {}", req);
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.getEmail(), req.getPassword())
        );
        User user = userRepository.findByEmail(req.getEmail())
                .orElseThrow(() -> new IllegalArgumentException("Invalid credentials provided!"));
        String jwt = jwtService.generateToken(new HashMap<>(), user);
        log.info("AuthService signin: success");
        return JwtAuthResponse.builder().token(jwt).build();
    }
}
