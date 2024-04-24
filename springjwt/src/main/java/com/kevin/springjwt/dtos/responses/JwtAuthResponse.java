package com.kevin.springjwt.dtos.responses;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class JwtAuthResponse {
    private String token;
}
