package com.kevin.springjwt.dtos.requests;

import lombok.Data;

@Data
public class SignUpRequest {
    private String email;
    private String username;
    private String password;
}
