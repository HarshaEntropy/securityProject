package com.imaginnovate.securityOAuth.controller;

import com.imaginnovate.securityOAuth.Exceptions.CustomException;
import com.imaginnovate.securityOAuth.Exceptions.UserNotFoundException;
import com.imaginnovate.securityOAuth.common.APIResponse;
import com.imaginnovate.securityOAuth.dto.*;
import com.imaginnovate.securityOAuth.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;


@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            return APIResponse.success("Login successfully", userService.authenticateUser(loginRequest));
        } catch (AuthenticationException e){
            return APIResponse.error("Bad credentials");
        }
    }

    @PostMapping("/signup")
    public ResponseEntity<APIResponse> createUser(@Valid @RequestBody UserCreationDTO userRequestDTO) {
        try {
            return APIResponse.success("Created successfully", new UserResponseDTO(userService.createUser(userRequestDTO)));
        } catch (RuntimeException e) {
            return APIResponse.error(e.getMessage());
        } catch (Exception e) {
            return APIResponse.error("Operation field please try again");
        }
    }

    @PostMapping("/changepassword")
    public ResponseEntity<APIResponse> changePassword(@Valid @RequestBody PasswordChangeDTO passwordChangeDTO) {
        try {
            userService.changePassword(passwordChangeDTO.getUserId(), passwordChangeDTO.getOldPassword(), passwordChangeDTO.getNewPassword());
            return  APIResponse.success( "Password changed successfully",null);
        } catch (CustomException e){
            return APIResponse.error(e.getHttpStatus(), e.getMessage());
        }
        catch (RuntimeException e){
            return APIResponse.error(e.getMessage());
        }
    }


    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody TokenRefreshRequest request) {
        try{
            return APIResponse.success(userService.refreshToken(request));
        } catch (CustomException e){
            return APIResponse.error(e.getHttpStatus(), e.getMessage());
        }
        catch (RuntimeException e){
            return APIResponse.error(e.getMessage());
        }
    }

}
