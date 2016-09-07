package com.imscd.mabo.security;

import com.imscd.mabo.domain.ResponseAuthorities;
import com.imscd.mabo.security.services.UserService;
import com.imscd.poc.exceptions.JWTTokenException;
import com.imscd.poc.security.JWTManager;
import org.springframework.http.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Created by Christian Sperandio on 16/07/2016.
 */
public final class TokenHandler {

    static private final String MABO_TOKEN = "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL3NlcnZpY2VzLmltc2NkLmNvbSIsImF1ZCI6ImE1MDA5ZGFhLTgwM2ItNDU1Zi05YjhmLTljM2JmOTdmYzk4OSIsInN1YiI6Im1hYm8iLCJleHAiOjE1MDQ4MTg5MjUsImlhdCI6MTQ3MzI4MjkyNX0.YhmM2jQhjqg9xrXXxOh8vH4ZlZ4y3Vrs6yJyL596GN0";
    private final JWTManager jwtManager;


    public TokenHandler(JWTManager jwtManager) {
        this.jwtManager = jwtManager;
    }

    public Optional<User> parseUserFromHeader(String token) throws JWTTokenException {

        Map<String, Object> claims = jwtManager.getClaims(token);
        String apiKey = (String) claims.get("aud");
        String login = (String) claims.get("sub");

        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", MABO_TOKEN);
        headers.set("application-code", "clotho");

        HttpEntity<String> entity = new HttpEntity<>("", headers);

        ResponseEntity<ResponseAuthorities> responseEntity = restTemplate.exchange("http://localhost:1111/permissions/company/" + apiKey + "/application/mabo/user/" + login,
                HttpMethod.GET, entity, ResponseAuthorities.class);


        if (responseEntity.getStatusCode() != HttpStatus.OK) {
            throw new JWTTokenException("Clotho communication failed.");
        }

        List<GrantedAuthority> authorities = responseEntity.getBody().getAuthorities()
                .stream()
                .map(x -> new SimpleGrantedAuthority(x))
                .collect(Collectors.toList());

        User user = new User(responseEntity.getBody().getLogin(), "", authorities);

        return Optional.of(user);
    }
}