package com.imscd.mabo.domain.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpSession;

/**
 * Created by Christian Sperandio on 14/08/2016.
 */
@Controller
public class MaboController {
    @Autowired
    HttpSession session;

    @RequestMapping("/")
    public String home(@RequestParam(name = "token", required = false, defaultValue = "") String token) {
        session.setAttribute("token", token);
        return "home";
    }

    @RequestMapping("/admin")
    public String admin() {

        return "admin";
    }

    @RequestMapping("/user")
    public String user() {
        return "user";
    }

    @RequestMapping("/authfailed")
    public String authFailed() {
        return "errors/401";
    }
}
