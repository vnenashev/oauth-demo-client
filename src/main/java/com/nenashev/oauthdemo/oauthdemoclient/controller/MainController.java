package com.nenashev.oauthdemo.oauthdemoclient.controller;

import com.nenashev.oauthdemo.oauthdemoclient.config.OauthConfig;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

@Controller
@RequestMapping(path = "/")
public class MainController {

    private final Logger logger = LoggerFactory.getLogger(MainController.class);

    private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();

    private final OauthConfig oauthConfig;
    private final SecureRandom secureRandom;

    public MainController(final OauthConfig oauthConfig,
                          final SecureRandom secureRandom) {
        this.oauthConfig = oauthConfig;
        this.secureRandom = secureRandom;

        logger.info("Initialized main controller with OAuth config: {}", oauthConfig);
    }

    @GetMapping(path = "/")
    public String index() {
        return "index";
    }

    @GetMapping(path = "/authorize")
    public String authorize() {
        final UriComponentsBuilder redirectUriBuilder =
            UriComponentsBuilder.fromUriString(oauthConfig.getAuthServerAuthorizationEndpoint());

        final byte[] stateBytes = new byte[64];
        secureRandom.nextBytes(stateBytes);
        final String state = new String(encoder.encode(stateBytes), StandardCharsets.UTF_8);

        redirectUriBuilder.queryParam("response_type", "code");
        redirectUriBuilder.queryParam("client_id", oauthConfig.getClientId());
        redirectUriBuilder.queryParam("redirect_uri", oauthConfig.getRedirectUris().get(0));
        redirectUriBuilder.queryParam("state", state);

        final UriComponents redirectUri = redirectUriBuilder.encode().build();
        return "redirect:" + redirectUri.toUriString();
    }
}
