package com.imaginnovate.securityOAuth.common;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.imaginnovate.securityOAuth.Exceptions.CustomException;
import com.imaginnovate.securityOAuth.annotation.OnlyRole;
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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.io.IOException;
import java.lang.reflect.Method;
import java.security.Key;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Log4j2
public class AuthTokenFilter extends OncePerRequestFilter {

    @Value("${imaginnovate.app.jwtSecret}")
    private String jwtSecret;

    @Autowired
    private MyUserDetailsService userDetailsService;

    @Autowired
    private RequestMappingHandlerMapping requestMappingHandlerMapping;  // Inject the RequestMappingHandlerMapping bean

    // Other existing code...

    private Method getHandlerMethod(HttpServletRequest request) {
        try {
            // Use the RequestMappingHandlerMapping to find the handler for the request
            HandlerMethod handlerMethod = (HandlerMethod) requestMappingHandlerMapping.getHandler(request).getHandler();
            return handlerMethod.getMethod();
        } catch (Exception e) {
            log.error("Unable to get handler method", e);
            return null;
        }
    }
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String jwt = parseJwt(request);
            if (jwt != null && validateJwtToken(jwt, false)) {
                String id = getUserNameFromJwtToken(jwt);

                MyUserDetails userDetails = (MyUserDetails) userDetailsService.loadUserByUsername(id);
                var context = SecurityContextHolder.createEmptyContext();
                context.setAuthentication(new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities()));
                SecurityContextHolder.setContext(context);

                // Extract and validate roles
                if (!hasRequiredRoles(request, userDetails)) {
                    throw new CustomException("You don't have permission to perform this action", HttpStatus.FORBIDDEN);
                }
            }
        } catch (CustomException ex) {
            response.setStatus(ex.getHttpStatus().value());

            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);

            final Map<String, Object> body = new HashMap<>();
            body.put("status", HttpServletResponse.SC_FORBIDDEN);
            body.put("error", "FORBIDDEN");
            body.put("message", ex.getMessage());
            body.put("path", request.getServletPath());

            final ObjectMapper mapper = new ObjectMapper();
            try {
                mapper.writeValue(response.getOutputStream(), body);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return;
        }
        filterChain.doFilter(request, response);
    }

    private boolean hasRequiredRoles(HttpServletRequest request, MyUserDetails userDetails) {
        // Get the handler method for the current request
        Method handlerMethod = getHandlerMethod(request);

        if (handlerMethod != null) {
            // Extract @OnlyRole annotation from the method
            OnlyRole onlyRoleAnnotation = AnnotationUtils.findAnnotation(handlerMethod, OnlyRole.class);
            if (onlyRoleAnnotation != null) {
                String[] requiredRoles = getRoleList(onlyRoleAnnotation.roles());

                // Get user roles
                Set<String> userRoles = userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet());

                // Check if user has any of the required roles
                return userRoles.stream().anyMatch(role -> Arrays.asList(requiredRoles).contains(role));
            }
        }

        return true; // If no @OnlyRole annotation is present, allow access
    }


    private String[] getRoleList(String rolesExpression) {
        if (rolesExpression.startsWith("hasAuthority(") && rolesExpression.endsWith(")")) {
            String rolesSubstring = rolesExpression.substring("hasAuthority(".length(), rolesExpression.length() - 1);
            return rolesSubstring.replace("'", "").split(",");
        }

        return rolesExpression.split(",");
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
