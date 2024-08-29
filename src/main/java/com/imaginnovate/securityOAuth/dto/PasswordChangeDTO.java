package com.imaginnovate.securityOAuth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class PasswordChangeDTO {
    @NotNull
    private Integer userId;

    @NotBlank
    private String oldPassword;

    @NotBlank
    private String newPassword;

    // Getters and setters
}
