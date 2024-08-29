package com.imaginnovate.securityOAuth.service;

import com.imaginnovate.securityOAuth.Exceptions.CustomException;
import com.imaginnovate.securityOAuth.Exceptions.InvalidUserIdentifierException;
import com.imaginnovate.securityOAuth.Exceptions.UserNotFoundException;
import com.imaginnovate.securityOAuth.common.APIResponse;
import com.imaginnovate.securityOAuth.common.TokenRefreshException;
import com.imaginnovate.securityOAuth.dto.*;
import com.imaginnovate.securityOAuth.entity.User;
import com.imaginnovate.securityOAuth.model.MyUserDetails;
import com.imaginnovate.securityOAuth.repository.UserRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.server.ResponseStatusException;

import java.security.Key;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService {

    @Value("${imaginnovate.app.jwtSecret}")
    private String jwtSecret;

    @Value("${imaginnovate.app.jwAccessTokenExpirationMs}")
    private int jwAccessTokenExpirationMs;
    @Value("${imaginnovate.app.jwtRefreshExpirationMs}")
    private int jwtRefreshExpirationMs;

    private final UserRepository userRepository;

    private final AuthenticationManager authenticationManager;

    private final PasswordEncoder passwordEncoder;

    public User createUser(UserCreationDTO userRequestDTO) {
    if (userRepository.findByUsername(userRequestDTO.getUsername()).isPresent()) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username is already taken");
    }
    User newUser = new User(userRequestDTO);
    newUser.setPassword(passwordEncoder.encode(userRequestDTO.getPassword()));
        return  userRepository.save(newUser);
    }

    public void changePassword(Integer userId, String oldPassword, String newPassword) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            throw new CustomException("Invalid old password",HttpStatus.BAD_REQUEST);
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }

    public ResponseEntity getAllUsers(int pageNumber, int pageSize, String searchTerm, String sortBy, String orderBy) {

        Sort.Direction direction = orderBy.equalsIgnoreCase("desc") ? Sort.Direction.DESC : Sort.Direction.ASC;

        PageRequest pageRequest = PageRequest.of(pageNumber, pageSize, Sort.by(direction, sortBy));

        Page<User> userPage;

        if (searchTerm != null && !searchTerm.isEmpty()) {
            userPage = userRepository.findByUsernameContainingOrFirstNameContainingOrLastNameContaining(
                    searchTerm, searchTerm, searchTerm, pageRequest);
        } else {
            userPage = userRepository.findAll(pageRequest);
        }
        List<UserResponseDTO> userResponseDTOS = userPage
                .stream()
                .map(UserResponseDTO::new)
                .collect(Collectors.toList());
        return ResponseEntity.ok(userResponseDTOS);

    }



    public User updateUser(Integer id, UserUpdateDTO userUpdateDTO) {
        User existingUser = userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException("User not found for update"));

        if (userUpdateDTO.getUsername() != null) {
            existingUser.setUsername(userUpdateDTO.getUsername());
        }
        if (userUpdateDTO.getFirstName() != null) {
            existingUser.setFirstName(userUpdateDTO.getFirstName());
        }
        if (userUpdateDTO.getLastName() != null) {
            existingUser.setLastName(userUpdateDTO.getLastName());
        }
        if (userUpdateDTO.getEmailAddress() != null) {
            existingUser.setEmailAddress(userUpdateDTO.getEmailAddress());
        }
        if (userUpdateDTO.getBirthdate() != null) {
            existingUser.setBirthdate(userUpdateDTO.getBirthdate());
        }
        if (userUpdateDTO.getPassword() != null) {
            existingUser.setPassword(passwordEncoder.encode(userUpdateDTO.getPassword()));
        }

        return userRepository.save(existingUser);
    }


    public User getUserById(Integer id) {
        if (id == null) {
            throw new InvalidUserIdentifierException("User Id cannot be null");
        }
        Optional<User> userOpt = userRepository.findById(id);
        if (userOpt.isPresent()) {
            return userOpt.get();
        }
        throw new UserNotFoundException(String.format("User not found for Id = %s", id));
    }

    @Transactional
    public APIResponse deleteUserById(Integer id) {
        if (id == null) {
            throw new InvalidUserIdentifierException("Id cannot be null");
        }
        User user = userRepository.findById(id).orElseThrow(() -> new UserNotFoundException(String.format("User not found")));
        userRepository.delete(user);
        return APIResponse.success("User has been deleted", null).getBody();
    }

    public JwtResponse authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername().toLowerCase(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = generateJwtToken(authentication);
        String refreshToken = generateJwtRefreshToken(authentication);
        return new JwtResponse(jwt, refreshToken);
    }

    private String generateJwtToken(Authentication authentication) {
        UserDetails userPrincipal = (MyUserDetails) authentication.getPrincipal();

        return Jwts.builder()
                .claim("username", userPrincipal.getUsername())
//                .claim("name",userPrincipal)
                .setSubject(userPrincipal.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwAccessTokenExpirationMs))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateJwtRefreshToken(Authentication authentication) {

        MyUserDetails userPrincipal = (MyUserDetails) authentication.getPrincipal();

        return Jwts.builder()
                .claim("username", userPrincipal.getUsername())
                .setSubject(userPrincipal.getUsername())
                .claim("name",userPrincipal.getFirstNameAndLastName())
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtRefreshExpirationMs))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public Object refreshToken(TokenRefreshRequest request) {
        String requestRefreshToken = request.getRefreshToken();
        if (requestRefreshToken != null && validateJwtToken(requestRefreshToken, true)) {
            String userName = getUsernameFromJwtToken(requestRefreshToken);
            User user = userRepository.findByUsername(userName).orElseThrow(() -> new UserNotFoundException("User not found"));
            String token = generateJwtToken(user.getUsername());
            return new TokenRefreshResponse(token, requestRefreshToken);
        } else {
            throw new TokenRefreshException(requestRefreshToken, "Refresh token is not in database!");
        }
    }

    public String generateJwtToken(String username) {
        return Jwts.builder()
                .claim("username",username)
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwAccessTokenExpirationMs))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String getUsernameFromJwtToken(String token) {
        final Claims claims = extractAllClaims(token);
        return (String) claims.get("username");
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
    public boolean validateJwtToken(String authToken, Boolean isRefreshToken) {
        try {
            Jwts.parserBuilder().setSigningKey(getSignInKey()).build().parse(authToken);
            return true;
        } catch (SignatureException | MalformedJwtException e) {
            throw isRefreshToken ? new CustomException("Invalid JWT token", HttpStatus.FORBIDDEN) : new CustomException("Invalid JWT token", HttpStatus.UNAUTHORIZED);
        } catch (UnsupportedJwtException e) {
            throw isRefreshToken ? new CustomException("JWT token is unsupported", HttpStatus.FORBIDDEN) : new CustomException("JWT token is unsupported", HttpStatus.UNAUTHORIZED);
        } catch (ExpiredJwtException expiredException) {
            throw isRefreshToken ? new CustomException("JWT token has expired", HttpStatus.FORBIDDEN) : new CustomException("JWT token has expired", HttpStatus.UNAUTHORIZED);
        } catch (IllegalArgumentException e) {
            throw isRefreshToken ? new CustomException("JWT claims string is empty", HttpStatus.FORBIDDEN) : new CustomException("JWT claims string is empty", HttpStatus.UNAUTHORIZED);
        }
    }
}
