package com.acoldbottle.security1.config.auth;

import com.acoldbottle.security1.domain.User;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;


/***
 * 시큐리티가 /login 주소 요청이 오면 낚아채서 로그인을 진행
 * 로그인 진행이 완료가 되면 session을 만들어준다(Security ContextHolder)
 * 오브젝트 타입 => Authentication 타입 객체
 * Authentication 안에 User정보가 있어야 됨
 * User 오브젝트 타입 => UserDetails 타입 객체
 * Security Session -> Authentication -> UserDetails(PrincipalDetails)
 */
@Getter
public class PrincipalDetails implements UserDetails, OAuth2User {

    private final User user;
    private Map<String, Object> attributes;

    // 일반 로그인
    public PrincipalDetails(User user) {
        this.user = user;
    }
    // OAuth 로그인
    public PrincipalDetails(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    // 해당 유저의 권한을 return
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return String.valueOf(user.getRole());
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public String getName() {
        return null;
    }
}
