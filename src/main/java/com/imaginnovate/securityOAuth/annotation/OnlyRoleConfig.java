package com.imaginnovate.securityOAuth.annotation;

import com.imaginnovate.securityOAuth.Exceptions.CustomException;
import com.imaginnovate.securityOAuth.common.AuthUtils;
import com.imaginnovate.securityOAuth.entity.User;
import jakarta.servlet.http.HttpServletRequest;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.HandlerMapping;

import java.util.Map;

@Aspect
@Configuration
public class OnlyRoleConfig {



    private AuthUtils authUtils;
    @Before("@annotation(OnlyRole) ")
    public void beforeValidateOrganization(JoinPoint joinPoint) throws Throwable {
        try {

            User loggedInUser = authUtils.getLoggedInUser();

            if (loggedInUser.getAuthorities()){
                return;
            }

            HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
            Map<String, String> uriVariables = (Map<String, String>) request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
            OnlyRole onlyRole =((MethodSignature) joinPoint.getSignature()).getMethod().getAnnotation(OnlyRole.class);
            String roles = uriVariables.get(onlyRole.roles());

        } catch (Exception e) {
            throw new CustomException("You don't have permission to perform this action", HttpStatus.FORBIDDEN);
        }
    }
}
