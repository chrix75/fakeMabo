package com.imscd.mabo.domain;

import com.auth0.jwt.internal.com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Created by Christian Sperandio on 17/07/2016.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class ResponseAuthorities {
    private String login;
    private String apikey;
    private List<String> authorities;

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public String getApikey() {
        return apikey;
    }

    public void setApikey(String apikey) {
        this.apikey = apikey;
    }

    public List<String> getAuthorities() {
        return authorities;
    }

    public void setAuthorities(List<String> authorities) {
        this.authorities = authorities;
    }
}
