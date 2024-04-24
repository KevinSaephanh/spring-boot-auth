package com.kevin.springjwt.dtos.requests;

import lombok.Data;

@Data
public class SigninRequest {
    private String username;
    private String email;
    private String password;
}
