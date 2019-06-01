package com.nenashev.oauthdemo.oauthdemoclient.config;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties("oauth.client")
public class OauthConfig {

    private String clientId;
    private String clientSecret;
    private List<String> redirectUris = new ArrayList<>();
    private Set<String> scope = new LinkedHashSet<>();

    private String authServerAuthorizationEndpoint;
    private String authServerTokenEndpoint;

    private String resourceUrl;

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

    public Set<String> getScope() {
        return scope;
    }

    public void setScope(final Set<String> scope) {
        this.scope = scope;
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

    public String getResourceUrl() {
        return resourceUrl;
    }

    public void setResourceUrl(final String resourceUrl) {
        this.resourceUrl = resourceUrl;
    }

    @Override
    public String toString() {
        return "OauthConfig{" +
            "clientId='" + clientId + '\'' +
            ", clientSecret='" + "<HIDDEN>" + '\'' +
            ", redirectUris=" + redirectUris +
            ", scope=" + scope +
            ", authServerAuthorizationEndpoint='" + authServerAuthorizationEndpoint + '\'' +
            ", authServerTokenEndpoint='" + authServerTokenEndpoint + '\'' +
            ", resourceUrl='" + resourceUrl + '\'' +
            '}';
    }
}
