package com.duark.security_jwt.entities.dto;

public record LoginResponse(String accessToken, Long expiresIn) {
}
