package com.kevin.springjwt.controllers;

import com.kevin.springjwt.dtos.requests.SignUpRequest;
import com.kevin.springjwt.dtos.requests.SigninRequest;
import com.kevin.springjwt.dtos.responses.JwtAuthResponse;
import com.kevin.springjwt.services.AuthService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private AuthService authService;

    @PostMapping("/signup")
    @ResponseBody
    public JwtAuthResponse signup(@RequestBody SignUpRequest req) {
        log.info("AuthController signup: signing up with {}", req);
        return authService.signup(req);
    }

    @PostMapping("/signin")
    @ResponseBody
    public JwtAuthResponse signin(@RequestBody SigninRequest req) {
        log.info("AuthController signin: signing in with {}", req);
        return authService.signin(req);
    }
}
