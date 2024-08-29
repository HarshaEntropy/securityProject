package com.imaginnovate.securityOAuth.dto;

import lombok.Data;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;
@Data
public class JwtResponse {
//  private List<String> roles;

  private String accessToken;
  private String refreshToken;

  public JwtResponse(String accessToken, String refreshToken) {
    this.accessToken = accessToken;
    this.refreshToken=refreshToken;
  }}