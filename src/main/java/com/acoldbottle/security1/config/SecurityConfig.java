package com.acoldbottle.security1.config;

import com.acoldbottle.security1.config.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import static com.acoldbottle.security1.domain.Authorization.ADMIN;
import static com.acoldbottle.security1.domain.Authorization.MANAGER;

/**
 * 1.코드 받기(인증) 2.액세스 토큰(권한)
 * 3.사용자 프로필 정보를 가져오고 4-1.그 정보를 토대로 회원가입을 자동으로 진행시킴
 * 4-2.(이메일,전화번호,이름,아이디) 쇼핑몰 -> (집주소), 백화점몰 -> (VIP등급,일반등급)
 */
@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록
@EnableMethodSecurity(securedEnabled = true)
public class SecurityConfig {

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

    @Bean
    public BCryptPasswordEncoder pwdEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/user/**").authenticated() //user 라는 url 로 들어오면 인증이 필요하다.
                        .requestMatchers("/admin/**").hasAuthority(ADMIN.name())
                        .requestMatchers("/manager/**").hasAnyAuthority(MANAGER.name(), ADMIN.name()) //manager 으로 들어오는 MANAGER 인증 또는 ADMIN 인증이 필요하다는 뜻이다.
                        .anyRequest().permitAll()) //그리고 나머지 url 은 전부 권한을 허용해준다.
                .formLogin(form -> form
                        .loginPage("/loginForm")
                        .loginProcessingUrl("/login") // login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행
                        .defaultSuccessUrl("/"))
                .oauth2Login(oauth -> oauth
                        .loginPage("/loginForm")
                        .userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint
                                .userService(principalOauth2UserService))
                ); //구글 로그인이 완료된 뒤의 후처리가 필요함. Tip.코드X, (엑세스토큰+사용자 프로필 정보O)

        return http.build();
    }

}
