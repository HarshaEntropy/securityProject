package com.imaginnovate.securityOAuth.common;


import com.imaginnovate.securityOAuth.Exceptions.CustomException;
import com.imaginnovate.securityOAuth.model.MyUserDetails;
import com.imaginnovate.securityOAuth.service.MyUserDetailsService;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;
import java.security.Key;
import java.util.function.Function;

@Log4j2
public class AuthTokenFilter extends OncePerRequestFilter {

    @Value("${imaginnovate.app.jwtSecret}")
    private String jwtSecret;

    @Autowired
    private MyUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String jwt = parseJwt(request);
            if (jwt != null && validateJwtToken(jwt, false)) {
                String id = getUserNameFromJwtToken(jwt);

                MyUserDetails userDetails = (MyUserDetails) userDetailsService.loadUserByUsername(id);
                var context = SecurityContextHolder.createEmptyContext();
                context.setAuthentication(new UsernamePasswordAuthenticationToken(userDetails, null, null));
                SecurityContextHolder.setContext(context);
            }
        } catch (CustomException ex) {
            SecurityContextHolder.clearContext();
            response.sendError(ex.getHttpStatus().value(), ex.getMessage());
            return;
        }
        filterChain.doFilter(request, response);
    }

    public String getUserNameFromJwtToken(String token) {
        return extractId(token);
    }

    public String extractId(String token) {
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

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }

        return null;
    }
}
