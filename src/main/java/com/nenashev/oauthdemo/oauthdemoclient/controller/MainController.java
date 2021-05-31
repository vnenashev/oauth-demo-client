package com.nenashev.oauthdemo.oauthdemoclient.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nenashev.oauthdemo.oauthdemoclient.config.OauthConfig;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import javax.servlet.http.HttpServletRequest;

import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
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

import io.jaegertracing.Configuration;
import io.opentracing.Scope;
import io.opentracing.Span;
import io.opentracing.Tracer;
import static java.util.stream.Collectors.toSet;

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
    private final AtomicReference<String> refreshToken = new AtomicReference<>(null);
    private final AtomicReference<Instant> tokenExpireTimestamp = new AtomicReference<>(null);

    private final Tracer tracer = Configuration.fromEnv().getTracer();

    public MainController(final OauthConfig oauthConfig,
                          final SecureRandom secureRandom,
                          final CloseableHttpClient httpClient,
                          final ObjectMapper objectMapper
                         ) {
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
        modelMap.addAttribute("refreshToken", refreshToken.get());
        return "index";
    }

    @GetMapping(path = "/authorize")
    public String authorize(final HttpServletRequest request) {
        final Span span = tracer.buildSpan("authorize")
                                .withTag("remote_addr", request.getRemoteAddr())
                                .start();
        try (final Scope scope = tracer.activateSpan(span)) {
            span.log("Received /authorize request");
            this.accessToken.set(null);
            this.tokenExpireTimestamp.set(null);
            this.refreshToken.set(null);
            this.scope.clear();
            final UriComponentsBuilder authEndpointUriBuilder =
                UriComponentsBuilder.fromUriString(oauthConfig.getAuthServerAuthorizationEndpoint());

            final String newState = generateRandomString(64);
            state.set(newState);

            authEndpointUriBuilder.queryParam("response_type", "code");
            authEndpointUriBuilder.queryParam("client_id", oauthConfig.getClientId());
            authEndpointUriBuilder.queryParam("redirect_uri", oauthConfig.getRedirectUris().get(0));
            authEndpointUriBuilder.queryParam("state", newState);
            authEndpointUriBuilder.queryParam("scope", String.join(" ", oauthConfig.getScope()));
            final UriComponents redirectUri = authEndpointUriBuilder.encode().build();
            return "redirect:" + redirectUri.toUriString();
        }
    }

    @GetMapping(path = "/callback")
    public String callback(final @RequestParam Map<String, String> params,
                           final ModelMap modelMap
                          ) {
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
        if (!params.containsKey("redirect_to_resource")) {
            httpFormParams.add(new BasicNameValuePair(
                "redirect_uri",
                oauthConfig.getRedirectUris().get(0)
            ));
        } else {
            httpFormParams.add(new BasicNameValuePair(
                "redirect_uri",
                oauthConfig.getRedirectUris().get(1)
            ));
        }
        final HttpEntity httpEntity = new UrlEncodedFormEntity(httpFormParams, StandardCharsets.UTF_8);
        tokenRequest.setEntity(httpEntity);

        try (final CloseableHttpResponse response = httpClient.execute(tokenRequest);
             final InputStream responseInputStream = response.getEntity().getContent()
        ) {
            final int responseStatus = response.getStatusLine().getStatusCode();
            if (responseStatus >= 200 && responseStatus < 300) {
                final Map<String, Object> responseJson =
                    objectMapper.readValue(responseInputStream, MAP_TYPE_REFERENCE);
                final String responseAccessToken = (String) responseJson.get("access_token");
                final String responseRefreshToken = (String) responseJson.get("refresh_token");
                final String cscope = (String) responseJson.get("scope");
                final int expireInSeconds = ((Number) responseJson.get("expires_in")).intValue();
                tokenExpireTimestamp.set(Instant.now().plusSeconds(expireInSeconds));
                accessToken.set(responseAccessToken);
                refreshToken.set(responseRefreshToken);
                scope.clear();
                Optional.ofNullable(cscope)
                        .filter(StringUtils::hasText)
                        .map(c -> c.split(" "))
                        .map(Stream::of)
                        .map(s -> s.collect(toSet())).ifPresent(scope::addAll);

                logger.info("Got access token {}, scope: {}", responseAccessToken, scope);
                if (StringUtils.hasText(responseRefreshToken)) {
                    logger.info("Got refresh token: {}", responseRefreshToken);
                }

                if (params.containsKey("redirect_to_resource")) {
                    logger.info("Redirecting to /words");
                    return "redirect:/words";
                }

                modelMap.addAttribute("accessToken", responseAccessToken);
                modelMap.addAttribute("scope", String.join(" ", scope));
                modelMap.addAttribute("refreshToken", refreshToken.get());
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

    @GetMapping(path = "/words")
    public String words(final ModelMap modelMap) {
        logger.info("Received GET /words");
        modelMap.addAttribute("words", "");
        modelMap.addAttribute("timestamp", 0);
        modelMap.addAttribute("result", "noget");
        return "words";
    }

    @GetMapping(path = "/get_words")
    public String getWords(final ModelMap modelMap) {
        logger.info("Received GET /get_words");

        final String accessToken = this.accessToken.get();
        if (!StringUtils.hasText(accessToken)) {
            //no access token, redirect to obtain
            logger.info("No access token found, redirecting to authorization server to obtain...");
            return requestAuthorization();
        } else if (tokenExpireTimestamp.get() != null && tokenExpireTimestamp.get().isBefore(Instant.now())) {
            this.accessToken.set(null);
            this.tokenExpireTimestamp.set(null);
            return requestRefreshToken(modelMap);
        }
        logger.info("Making request with access token {}", accessToken);

        final HttpGet resourceRequest = new HttpGet(oauthConfig.getResourceUrl());
        resourceRequest.setHeader("Authorization", "Bearer " + accessToken);

        try (final CloseableHttpResponse response = httpClient.execute(resourceRequest);
             final InputStream responseInputStream = response.getEntity().getContent()
        ) {
            final int responseStatus = response.getStatusLine().getStatusCode();
            if (responseStatus >= 200 && responseStatus < 300) {
                final Map<String, Object> responseJson =
                    objectMapper.readValue(responseInputStream, MAP_TYPE_REFERENCE);
                modelMap.addAttribute("words", responseJson.get("words"));
                modelMap.addAttribute("timestamp", responseJson.get("timestamp"));
                modelMap.addAttribute("result", "get");
                return "words";
            } else {
                this.accessToken.set(null);
                this.tokenExpireTimestamp.set(null);
                if (this.refreshToken.get() != null) {
                    return requestRefreshToken(modelMap);
                } else {
                    modelMap.addAttribute("words", "");
                    modelMap.addAttribute("timestamp", 0);
                    modelMap.addAttribute("result", "noget");
                    return "words";
                }
            }
        } catch (final IOException e) {
            this.accessToken.set(null);
            this.tokenExpireTimestamp.set(null);
            logger.error("Exception caught:", e);
            modelMap.addAttribute("error", e.getMessage());
            return "error";
        }
    }

    @GetMapping(path = "/add_word")
    public String addWord(final ModelMap modelMap,
                          final @RequestParam("word") String word
                         ) {
        logger.info("Received GET /add_word");

        final String accessToken = this.accessToken.get();
        if (!StringUtils.hasText(accessToken)) {
            //no access token, redirect to obtain
            logger.info("No access token found, redirecting to authorization server to obtain...");
            return requestAuthorization();
        } else if (tokenExpireTimestamp.get() != null && tokenExpireTimestamp.get().isBefore(Instant.now())) {
            this.accessToken.set(null);
            this.tokenExpireTimestamp.set(null);
            return requestRefreshToken(modelMap);
        }
        logger.info("Making request with access token {}", accessToken);

        final HttpPost resourceRequest = new HttpPost(oauthConfig.getResourceUrl());
        resourceRequest.setHeader("Authorization", "Bearer " + accessToken);
        resourceRequest.setEntity(new UrlEncodedFormEntity(
            Collections.singletonList(new BasicNameValuePair("word", word)),
            StandardCharsets.UTF_8
        ));

        try (final CloseableHttpResponse response = httpClient.execute(resourceRequest)) {
            final int responseStatus = response.getStatusLine().getStatusCode();
            if (responseStatus >= 200 && responseStatus < 300) {
                modelMap.addAttribute("words", "");
                modelMap.addAttribute("timestamp", 0);
                modelMap.addAttribute("result", "add");
                return "words";
            } else {
                this.accessToken.set(null);
                this.tokenExpireTimestamp.set(null);
                if (this.refreshToken.get() != null) {
                    return requestRefreshToken(modelMap);
                } else {
                    modelMap.addAttribute("words", "");
                    modelMap.addAttribute("timestamp", 0);
                    modelMap.addAttribute("result", "noadd");
                    return "words";
                }
            }
        } catch (final IOException e) {
            this.accessToken.set(null);
            this.tokenExpireTimestamp.set(null);
            logger.error("Exception caught:", e);
            modelMap.addAttribute("error", e.getMessage());
            return "error";
        }
    }

    @GetMapping(path = "/delete_word")
    public String deleteWord(final ModelMap modelMap) {
        logger.info("Received GET /delete_word");

        final String accessToken = this.accessToken.get();
        if (!StringUtils.hasText(accessToken)) {
            //no access token, redirect to obtain
            logger.info("No access token found, redirecting to authorization server to obtain...");
            return requestAuthorization();
        } else if (tokenExpireTimestamp.get() != null && tokenExpireTimestamp.get().isBefore(Instant.now())) {
            this.accessToken.set(null);
            this.tokenExpireTimestamp.set(null);
            return requestRefreshToken(modelMap);
        }
        logger.info("Making request with access token {}", accessToken);

        final HttpDelete resourceRequest = new HttpDelete(oauthConfig.getResourceUrl());
        resourceRequest.setHeader("Authorization", "Bearer " + accessToken);

        try (final CloseableHttpResponse response = httpClient.execute(resourceRequest)) {
            final int responseStatus = response.getStatusLine().getStatusCode();
            if (responseStatus >= 200 && responseStatus < 300) {
                modelMap.addAttribute("words", "");
                modelMap.addAttribute("timestamp", 0);
                modelMap.addAttribute("result", "rm");
                return "words";
            } else {
                this.accessToken.set(null);
                this.tokenExpireTimestamp.set(null);
                if (this.refreshToken.get() != null) {
                    return requestRefreshToken(modelMap);
                } else {
                    modelMap.addAttribute("words", "");
                    modelMap.addAttribute("timestamp", 0);
                    modelMap.addAttribute("result", "norm");
                    return "words";
                }
            }
        } catch (final IOException e) {
            this.accessToken.set(null);
            this.tokenExpireTimestamp.set(null);
            logger.error("Exception caught:", e);
            modelMap.addAttribute("error", e.getMessage());
            return "error";
        }
    }

    private String requestAuthorization() {
        final UriComponentsBuilder authEndpointUriBuilder =
            UriComponentsBuilder.fromUriString(oauthConfig.getAuthServerAuthorizationEndpoint());

        final String newState = generateRandomString(64);
        state.set(newState);

        authEndpointUriBuilder.queryParam("response_type", "code");
        authEndpointUriBuilder.queryParam("client_id", oauthConfig.getClientId());
        authEndpointUriBuilder.queryParam(
            "redirect_uri",
            oauthConfig.getRedirectUris().get(1)
                                         );
        authEndpointUriBuilder.queryParam("state", newState);
        authEndpointUriBuilder.queryParam("scope", String.join(" ", oauthConfig.getScope()));

        final UriComponents redirectUri = authEndpointUriBuilder.encode().build();
        return "redirect:" + redirectUri.toUriString();
    }

    private String requestRefreshToken(final ModelMap modelMap) {
        logger.info("Refreshing access token...");
        final HttpPost tokenRequest = new HttpPost(oauthConfig.getAuthServerTokenEndpoint());
        tokenRequest.setHeader("Content-Type", MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        final byte[] authBytes = (oauthConfig.getClientId() + ":" + oauthConfig.getClientSecret())
            .getBytes(StandardCharsets.UTF_8);
        tokenRequest.setHeader("Authorization", "Basic " + encoder.encodeToString(authBytes));
        final List<NameValuePair> httpFormParams = new ArrayList<>(2);
        httpFormParams.add(new BasicNameValuePair("grant_type", "refresh_token"));
        httpFormParams.add(new BasicNameValuePair("refresh_token", refreshToken.get()));
        final HttpEntity httpEntity = new UrlEncodedFormEntity(httpFormParams, StandardCharsets.UTF_8);
        tokenRequest.setEntity(httpEntity);

        try (final CloseableHttpResponse response = httpClient.execute(tokenRequest);
             final InputStream responseInputStream = response.getEntity().getContent()
        ) {
            final int responseStatus = response.getStatusLine().getStatusCode();
            if (responseStatus >= 200 && responseStatus < 300) {
                final Map<String, Object> responseJson =
                    objectMapper.readValue(responseInputStream, MAP_TYPE_REFERENCE);
                final String responseAccessToken = (String) responseJson.get("access_token");
                final String responseRefreshToken = (String) responseJson.get("refresh_token");
                final int expireInSeconds = ((Number) responseJson.get("expires_in")).intValue();
                tokenExpireTimestamp.set(Instant.now().plusSeconds(expireInSeconds));
                accessToken.set(responseAccessToken);
                if (StringUtils.hasText(responseRefreshToken)) {
                    this.refreshToken.set(responseRefreshToken);
                    logger.info("Got refresh token: {}", responseRefreshToken);
                }
                logger.info("Got access token {}", responseAccessToken);

                return "redirect:/words";
            } else {
                logger.warn("Cannot get access token using refresh token, starting new authorization...");
                this.refreshToken.set(null);
                return "redirect:/authorize";
            }
        } catch (final IOException e) {
            logger.error("Exception caught:", e);
            modelMap.addAttribute("error", e.getMessage());
            return "error";
        }
    }

    private String generateRandomString(final int bytesLength) {
        final byte[] bytes = new byte[bytesLength];
        secureRandom.nextBytes(bytes);
        return new String(encoder.encode(bytes), StandardCharsets.UTF_8);
    }
}
