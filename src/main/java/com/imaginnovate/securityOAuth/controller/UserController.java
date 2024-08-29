package com.imaginnovate.securityOAuth.controller;

import com.imaginnovate.securityOAuth.Exceptions.InvalidUserIdentifierException;
import com.imaginnovate.securityOAuth.Exceptions.UserNotFoundException;
import com.imaginnovate.securityOAuth.annotation.OnlyRole;
import com.imaginnovate.securityOAuth.common.APIResponse;
import com.imaginnovate.securityOAuth.common.TestBody;
import com.imaginnovate.securityOAuth.dto.UserResponseDTO;
import com.imaginnovate.securityOAuth.dto.UserUpdateDTO;
import com.imaginnovate.securityOAuth.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/users")
public class UserController {


    private final UserService userService;


    @GetMapping
    public ResponseEntity getAppUserList(@RequestParam(defaultValue = "0") int pageNumber, @RequestParam(defaultValue = "5") int pageSize, @RequestParam(name = "search", defaultValue = "") String searchTerm, @RequestParam(defaultValue = "id") String sortBy, @RequestParam(defaultValue = "desc") String orderBy, @RequestBody TestBody testBody) {
        System.out.println("From the Best "+testBody.getTest());
        return userService.getAllUsers(pageNumber, pageSize, searchTerm, sortBy, orderBy);
    }

    @GetMapping("/{id}")
    @OnlyRole(roles = "hasAuthority('ROLE_ADMIN','ROLE_DEVELOPER')")
    public ResponseEntity<APIResponse> getUserById(@PathVariable("id") Integer id) {
        try {
            return APIResponse.success(new UserResponseDTO(userService.getUserById(id)));
        } catch (InvalidUserIdentifierException | UserNotFoundException e) {
            return APIResponse.error(e.getMessage());
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteById(@PathVariable("id") Integer id) {
        try {
            userService.deleteUserById(id);
            return APIResponse.success("Deleted successfully", null);
        } catch (UserNotFoundException e) {
            return APIResponse.error(e.getMessage());
        } catch (RuntimeException e) {
            return APIResponse.error(e.getMessage());
        }
    }
    @PutMapping("/{id}")
    public ResponseEntity<APIResponse> updateUser(@PathVariable("id") Integer id,
                                                  @Valid @RequestBody UserUpdateDTO userUpdateDTO) {
        try {
            UserResponseDTO updatedUser = new UserResponseDTO(userService.updateUser(id, userUpdateDTO));
            return APIResponse.success("Updated successfully", updatedUser);
        } catch (UserNotFoundException e) {
            return APIResponse.error(e.getMessage());
        } catch (RuntimeException e) {
            return APIResponse.error(e.getMessage());
        } catch (Exception e) {
            return APIResponse.error("Operation failed, please try again.");
        }
    }

}
