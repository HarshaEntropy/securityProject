package com.imaginnovate.securityOAuth.common;

import com.imaginnovate.securityOAuth.entity.User;
//import org.apache.tomcat.util.net.openssl.ciphers.Authentication;
import com.imaginnovate.securityOAuth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class AuthUtils {

    @Autowired
    private UserRepository userRepository;

    public User getLoggedInUser() throws RuntimeException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        return userRepository.findByUsername(username).orElseThrow(()->new RuntimeException("User not found"));
    }
}