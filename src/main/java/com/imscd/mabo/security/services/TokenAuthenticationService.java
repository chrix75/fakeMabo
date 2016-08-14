package com.imscd.mabo.security.services;

import com.imscd.mabo.security.TokenHandler;
import com.imscd.mabo.security.UserAuthentication;
import com.imscd.poc.exceptions.JWTTokenException;
import com.imscd.poc.security.JWTManager;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Created by Christian Sperandio on 16/07/2016.
 */
public class TokenAuthenticationService {

    private static final String AUTH_HEADER_NAME = "Authorization";

    private final TokenHandler tokenHandler;

    public TokenAuthenticationService(UserService userService, JWTManager jwtManager) {
        tokenHandler = new TokenHandler(jwtManager);
    }

    public Authentication getAuthentication(HttpServletRequest request) throws JWTTokenException {
        HttpSession session = ((HttpServletRequest) request).getSession(true);
        final String token = (String) session.getAttribute("token");
        if (token != null) {
            final Optional<User> user = tokenHandler.parseUserFromHeader(token);
            if (user.isPresent()) {
                User found = user.get();
                if (found.getAuthorities().size() > 0) {
                    return new UserAuthentication(found);
                }
            }
        }

        // Manage connections without token
        GrantedAuthority anonymous = new SimpleGrantedAuthority("ROLE_ANONYMOUS");
        List<GrantedAuthority> auths = new ArrayList<>();
        auths.add(anonymous);

        return new UserAuthentication(new User("ANONYNOUS USER", "", auths));
    }
}