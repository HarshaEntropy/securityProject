package com.imaginnovate.securityOAuth.common;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.imaginnovate.securityOAuth.Exceptions.CustomException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.ModelAndView;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class MyExceptionResolver implements HandlerExceptionResolver {

    @Override
    public ModelAndView resolveException(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) {
        if (ex instanceof UnauthorizedException) {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            return new ModelAndView("error/401");  // Make sure this view exists
        }
        if (ex instanceof CustomException exception){
            response.setStatus(exception.getHttpStatus().value());

            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

            final Map<String, Object> body = new HashMap<>();
            body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
            body.put("error", "Unauthorized");
            body.put("message", exception.getMessage());
            body.put("path", request.getServletPath());

            final ObjectMapper mapper = new ObjectMapper();
            try {
                mapper.writeValue(response.getOutputStream(), body);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            ModelAndView modelAndView = new ModelAndView("error/403"); // Ensure this view exists
            modelAndView.addObject("message", exception.getMessage());
            return modelAndView;
        }

        // For any other exception, return a generic error page or message
        response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        ModelAndView modelAndView = new ModelAndView("error/500"); // Ensure this view exists
        modelAndView.addObject("message", "An unexpected error occurred.");
        return modelAndView;
    }
}