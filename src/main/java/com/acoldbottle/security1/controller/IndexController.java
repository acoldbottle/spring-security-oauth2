package com.acoldbottle.security1.controller;

import com.acoldbottle.security1.config.auth.PrincipalDetails;
import com.acoldbottle.security1.domain.Authorization;
import com.acoldbottle.security1.domain.User;
import com.acoldbottle.security1.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import static com.acoldbottle.security1.domain.Authorization.*;

@Slf4j
@Controller
public class IndexController {

    @Autowired
    UserRepository userRepository;
    @Autowired
    BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/test/login")
    @ResponseBody
    public String testLogin(Authentication authentication, @AuthenticationPrincipal PrincipalDetails userDetails) {
        log.info("/test/login ==============");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        log.info("authentication={}", principalDetails.getUser());
        log.info("userDetails={}", userDetails.getUser().getUsername());
        return "세션 정보 확인하기";
    }
    @GetMapping("/test/oauth/login")
    @ResponseBody
    public String testOAuthLogin(Authentication authentication, @AuthenticationPrincipal OAuth2User oAuth) {
        log.info("/test/login ==============");
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        log.info("authentication={}", oAuth2User.getAttributes());
        log.info("oAuth={}", oAuth.getAttributes());
        return "OAuth 세션 정보 확인하기";
    }

    @GetMapping({"", "/"})
    public String index() {
        return "index";
    }

    @ResponseBody
    @GetMapping("/user")
    public String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        log.info("principalDetails={}", principalDetails.getUser());
        return "user";
    }

    @ResponseBody
    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }

    @ResponseBody
    @GetMapping("/manager")
    public String manager() {
        return "manager";
    }

    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    @ResponseBody
    @PostMapping("/join")
    public String join(User user) {
        System.out.println(user);
        user.setRole(USER);
        String rawPwd = user.getPassword();
        String encPwd = bCryptPasswordEncoder.encode(rawPwd);
        user.setPassword(encPwd);
        userRepository.save(user);
        return "join";
    }

    @Secured("ADMIN")
    @ResponseBody
    @GetMapping("/info")
    public String info() {
        return "INFO 페이지";
    }

}
