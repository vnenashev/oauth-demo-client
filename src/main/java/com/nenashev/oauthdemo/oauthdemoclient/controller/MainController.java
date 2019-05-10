package com.nenashev.oauthdemo.oauthdemoclient.controller;

import com.nenashev.oauthdemo.oauthdemoclient.config.OauthConfig;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(path = "/")
public class MainController {

    private final OauthConfig oauthConfig;

    public MainController(final OauthConfig oauthConfig) {
        this.oauthConfig = oauthConfig;
    }

    @GetMapping(path = "/")
    public String index() {
        return "index";
    }
}
