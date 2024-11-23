package com.example.securitySample.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class passwordConfig {

    @Bean
    public PasswordEncoder passworderer (){
        return new BCryptPasswordEncoder(10);
    }
}
