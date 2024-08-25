package com.acoldbottle.security1.config.auth;

import com.acoldbottle.security1.domain.User;
import com.acoldbottle.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// 시큐리티 설정에서 loginProcessionUrl("/login");
// login 요청이 오면 자동으로 UserDetailsService 타입으로 IoC 되어 있는 loadUserByUsername 함수가 실행
@Service
public class PrincipalDetailsService implements UserDetailsService {

    @Autowired
    UserRepository userRepository;

    /**
     * 시큐리티 Session(내부 Authentication(내부 UserDetails))
     * 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User userEntity = userRepository.findByUsername(username);
        if (username != null) {
            return new PrincipalDetails(userEntity);
        }
        return null;
    }
}
