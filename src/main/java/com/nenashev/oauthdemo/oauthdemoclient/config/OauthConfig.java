package com.nenashev.oauthdemo.oauthdemoclient.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties("oauth.client")
public class OauthConfig {

    private String clientId;
    private String clientSecret;
    private List<String> redirectUris = new ArrayList<>();

    private String authServerAuthorizationEndpoint;
    private String authServerTokenEndpoint;

    public String getClientId() {
        return clientId;
    }

    public void setClientId(final String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(final String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public List<String> getRedirectUris() {
        return redirectUris;
    }

    public void setRedirectUris(final List<String> redirectUris) {
        this.redirectUris = redirectUris;
    }

    public String getAuthServerAuthorizationEndpoint() {
        return authServerAuthorizationEndpoint;
    }

    public void setAuthServerAuthorizationEndpoint(final String authServerAuthorizationEndpoint) {
        this.authServerAuthorizationEndpoint = authServerAuthorizationEndpoint;
    }

    public String getAuthServerTokenEndpoint() {
        return authServerTokenEndpoint;
    }

    public void setAuthServerTokenEndpoint(final String authServerTokenEndpoint) {
        this.authServerTokenEndpoint = authServerTokenEndpoint;
    }

    @Override
    public String toString() {
        return "OauthConfig{" +
            "clientId='" + clientId + '\'' +
            ", clientSecret='" + "<HIDDEN>" + '\'' +
            ", redirectUris=" + redirectUris +
            ", authServerAuthorizationEndpoint='" + authServerAuthorizationEndpoint + '\'' +
            ", authServerTokenEndpoint='" + authServerTokenEndpoint + '\'' +
            '}';
    }
}
