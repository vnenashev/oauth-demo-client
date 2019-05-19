package com.nenashev.oauthdemo.oauthdemoclient.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nenashev.oauthdemo.oauthdemoclient.config.OauthConfig;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

@Controller
@RequestMapping(path = "/")
public class MainController {

    private final Logger logger = LoggerFactory.getLogger(MainController.class);

    private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();

    private static final TypeReference<Map<String, Object>> MAP_TYPE_REFERENCE
        = new TypeReference<Map<String, Object>>() {
    };

    private final OauthConfig oauthConfig;
    private final SecureRandom secureRandom;
    private final CloseableHttpClient httpClient;
    private final ObjectMapper objectMapper;

    private final Set<String> scope = ConcurrentHashMap.newKeySet();
    private final AtomicReference<String> state = new AtomicReference<>(null);
    private final AtomicReference<String> accessToken = new AtomicReference<>(null);

    public MainController(final OauthConfig oauthConfig,
                          final SecureRandom secureRandom,
                          final CloseableHttpClient httpClient,
                          final ObjectMapper objectMapper) {
        this.oauthConfig = oauthConfig;
        this.secureRandom = secureRandom;
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;

        logger.info("Initialized main controller with OAuth config: {}", oauthConfig);
    }

    @GetMapping(path = "/")
    public String index(final ModelMap modelMap) {
        modelMap.addAttribute("accessToken", accessToken.get());
        modelMap.addAttribute("scope", String.join(", ", scope));
        return "index";
    }

    @GetMapping(path = "/authorize")
    public String authorize() {
        final UriComponentsBuilder authEndpointUriBuilder =
            UriComponentsBuilder.fromUriString(oauthConfig.getAuthServerAuthorizationEndpoint());

        final byte[] stateBytes = new byte[64];
        secureRandom.nextBytes(stateBytes);
        final String newState = new String(encoder.encode(stateBytes), StandardCharsets.UTF_8);
        state.set(newState);

        authEndpointUriBuilder.queryParam("response_type", "code");
        authEndpointUriBuilder.queryParam("client_id", oauthConfig.getClientId());
        authEndpointUriBuilder.queryParam("redirect_uri", oauthConfig.getRedirectUris().get(0));
        authEndpointUriBuilder.queryParam("state", newState);
        authEndpointUriBuilder.queryParam("scope", String.join(" ", scope));

        final UriComponents redirectUri = authEndpointUriBuilder.encode().build();
        return "redirect:" + redirectUri.toUriString();
    }

    @GetMapping(path = "/callback")
    public String callback(final @RequestParam Map<String, String> params,
                           final ModelMap modelMap) {
        if (params.containsKey("error")) {
            modelMap.addAttribute("error", params.get("error"));
            return "error";
        }

        final String expectedState = state.get();
        final String reqState = params.get("state");

        if (!Objects.equals(expectedState, reqState)) {
            logger.error("State DOES NOT MATCH: expected {}, got {} ", expectedState, reqState);
            modelMap.addAttribute("error", "State value did not match");
            return "error";
        }

        final HttpPost tokenRequest = new HttpPost(oauthConfig.getAuthServerTokenEndpoint());
        tokenRequest.setHeader("Content-Type", MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        final byte[] authBytes = (oauthConfig.getClientId() + ":" + oauthConfig.getClientSecret())
            .getBytes(StandardCharsets.UTF_8);
        tokenRequest.setHeader("Authorization", "Basic " + encoder.encodeToString(authBytes));
        final List<NameValuePair> httpFormParams = new ArrayList<>(3);
        httpFormParams.add(new BasicNameValuePair("grant_type", "authorization_code"));
        httpFormParams.add(new BasicNameValuePair("code", params.get("code")));
        httpFormParams.add(new BasicNameValuePair("redirect_uri",
            oauthConfig.getRedirectUris().get(0)));
        final HttpEntity httpEntity = new UrlEncodedFormEntity(httpFormParams, StandardCharsets.UTF_8);
        tokenRequest.setEntity(httpEntity);

        try (final CloseableHttpResponse response = httpClient.execute(tokenRequest);
             final InputStream responseInputStream = response.getEntity().getContent()) {
            final int responseStatus = response.getStatusLine().getStatusCode();
            if (responseStatus >= 200 && responseStatus < 300) {
                final Map<String, Object> responseJson =
                    objectMapper.readValue(responseInputStream, MAP_TYPE_REFERENCE);
                final String responseAccessToken = (String) responseJson.get("access_token");
                accessToken.set(responseAccessToken);
                logger.info("Got access token {}", responseAccessToken);

                if (params.containsKey("redirect_to_resource")) {
                    logger.info("Redirecting to /fetch_resource");
                    return "redirect:/fetch_resource";
                }

                modelMap.addAttribute("accessToken", responseAccessToken);
                modelMap.addAttribute("scope", String.join(" ", scope));
                return "index";
            } else {
                modelMap.addAttribute("error", "Unable to fetch access token," +
                    " server response: " + responseStatus);
                return "error";
            }
        } catch (final IOException e) {
            logger.error("Exception caught:", e);
            modelMap.addAttribute("error", e.getMessage());
            return "error";
        }
    }

    @GetMapping(path = "/fetch_resource")
    public String fetchResource(final ModelMap modelMap) {
        logger.info("Received GET /fetch_resource");
        final String accessToken = this.accessToken.get();
        if (!StringUtils.hasText(accessToken)) {
            //no access token, redirect to obtain
            logger.info("No access token found, redirecting to authorization server to obtain...");
            final UriComponentsBuilder authEndpointUriBuilder =
                UriComponentsBuilder.fromUriString(oauthConfig.getAuthServerAuthorizationEndpoint());

            final byte[] stateBytes = new byte[64];
            secureRandom.nextBytes(stateBytes);
            final String newState = new String(encoder.encode(stateBytes), StandardCharsets.UTF_8);
            state.set(newState);

            authEndpointUriBuilder.queryParam("response_type", "code");
            authEndpointUriBuilder.queryParam("client_id", oauthConfig.getClientId());
            authEndpointUriBuilder.queryParam("redirect_uri",
                oauthConfig.getRedirectUris().get(1));
            authEndpointUriBuilder.queryParam("state", newState);
            authEndpointUriBuilder.queryParam("scope", String.join(" ", scope));

            final UriComponents redirectUri = authEndpointUriBuilder.encode().build();
            return "redirect:" + redirectUri.toUriString();
        }
        logger.info("Making request with access token {}", accessToken);

        final HttpPost resourceRequest = new HttpPost(oauthConfig.getResourceUrl());
        resourceRequest.setHeader("Authorization", "Bearer " + accessToken);

        try (final CloseableHttpResponse response = httpClient.execute(resourceRequest);
             final InputStream responseInputStream = response.getEntity().getContent()) {
            final int responseStatus = response.getStatusLine().getStatusCode();
            if (responseStatus >= 200 && responseStatus < 300) {
                final Map<String, Object> responseJson =
                    objectMapper.readValue(responseInputStream, MAP_TYPE_REFERENCE);
                final String printedResource = objectMapper
                    .writerWithDefaultPrettyPrinter()
                    .writeValueAsString(responseJson);
                modelMap.addAttribute("resource", printedResource);
                return "data";
            } else {
                this.accessToken.set(null);
                modelMap.addAttribute("error", "Unable to fetch resource," +
                    " server response: " + responseStatus);
                return "error";
            }
        } catch (final IOException e) {
            this.accessToken.set(null);
            logger.error("Exception caught:", e);
            modelMap.addAttribute("error", e.getMessage());
            return "error";
        }
    }
}
