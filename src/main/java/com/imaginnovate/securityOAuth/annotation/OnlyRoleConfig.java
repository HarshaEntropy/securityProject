package com.imaginnovate.securityOAuth.annotation;

import com.imaginnovate.securityOAuth.Exceptions.CustomException;
import com.imaginnovate.securityOAuth.common.AuthUtils;
import com.imaginnovate.securityOAuth.entity.Authority;
import com.imaginnovate.securityOAuth.entity.User;
import lombok.RequiredArgsConstructor;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Aspect
@Configuration
@RequiredArgsConstructor
public class OnlyRoleConfig {

    private final AuthUtils authUtils;

//    @Before("@annotation(onlyRole)")
    public void beforeValidateRole(JoinPoint joinPoint, OnlyRole onlyRole) throws Throwable {
        try {
            if (onlyRole.equals("All")) {
                return;
            }
            User user = authUtils.getLoggedInUser();
            Set<String> userRoles = user.getAuthorities().stream()
                    .map(Authority::getAuthority)
                    .collect(Collectors.toSet());

            List<String> requiredRoles = getRoleList(onlyRole.roles());

            // Check if the user has any of the required roles
            boolean hasRequiredRole = userRoles.stream()
                    .anyMatch(requiredRoles::contains);

            if (!hasRequiredRole) {
                throw new CustomException("You don't have permission to perform this action",HttpStatus.FORBIDDEN);
            }
        } catch (CustomException e) {
            // Re-throw CustomException to let it propagate to the global exception handler
            throw e;
        }catch (Exception  e) {
            throw new CustomException("You don't have permission to perform this action", HttpStatus.FORBIDDEN);
        }
    }

    private List<String> getRoleList(String rolesExpression) {
        // Check if the roles expression uses the 'hasAuthority' format
        if (rolesExpression.startsWith("hasAuthority(") && rolesExpression.endsWith(")")) {
            // Extract the roles within the parentheses
            String rolesSubstring = rolesExpression.substring("hasAuthority(".length(), rolesExpression.length() - 1);
            // Remove single quotes and split by commas
            return List.of(rolesSubstring.replace("'", "").split(","));
        }

        // Default case: split by commas directly
        return List.of(rolesExpression.split(","));
    }
}
