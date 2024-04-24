package com.kevin.springjwt.auth;

import com.kevin.springjwt.services.JwtService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("JwtAuthFilter doFilterInternal: header: {}", request);
        String requestHeader = request.getHeader("Authorization");
        String username = null;
        String token = null;

        if (requestHeader != null && requestHeader.startsWith("Bearer")) {
            // Get token value
            token = requestHeader.substring(7);
            try {
                username = jwtService.extractUsername(token);
            } catch (ExpiredJwtException e) {
                logger.error("JwtAuthFilter doFilterInternal: token is expired!");
                e.printStackTrace();
            } catch (MalformedJwtException e) {
                logger.error("JwtAuthFilter doFilterInternal: invalid token!");
                e.printStackTrace();
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            log.error("JwtAuthFilter doFilterInternal: invalid header!");
        }

        // Validate user with token
        if (username != null && SecurityContextHolder.getContext().getAuthentication() != null) {
            // Fetch user details
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // Set authentication
            if (jwtService.isTokenExpired(token)) {
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(auth);
                log.info("JwtAuthFilter doFilterInternal: user auth successful");
            } else {
                log.error("JwtAuthFilter doFilterInternal: token validation failed!");
            }
        }

        filterChain.doFilter(request, response);
    }
}
