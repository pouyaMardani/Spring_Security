package com.example.securitySample.security;

import com.example.securitySample.auth.ApplicationUserService;
import com.example.securitySample.jwt.JwtTokenVerifier;
import com.example.securitySample.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig {

    private final PasswordEncoder PASSWORD_ENCODER;
    private final ApplicationUserService applicationUserService;


    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService) {
        this.PASSWORD_ENCODER = passwordEncoder;
        this.applicationUserService = applicationUserService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager))
                .addFilterAfter(new JwtTokenVerifier(), JwtUsernameAndPasswordAuthenticationFilter.class)

                .authorizeHttpRequests((auth) ->
                        auth
                                .requestMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())
                                .anyRequest().authenticated()

                )
               /* .formLogin().loginPage("/login").permitAll().defaultSuccessUrl("/index.html", true)
                .and()
                .logout()
                .logoutUrl("/logout")
                .clearAuthentication(true)
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .logoutSuccessUrl("/login")*/
        ;

        return http.build();
    }


    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class).build();
    }


/*
    @Bean
    protected UserDetailsService  userDetailsService (){
        UserDetails annasmith = User.builder()
                .username("annasmith")
                .password(PASSWORD_ENCODER.encode("password"))
                .authorities(ApplicationUserRole.STUDENT.getGrantedAuthorities())
               // .roles(ApplicationUserRole.STUDENT.name())
                .build();

        UserDetails linda = User.builder()
                .username("linda")
                .password(PASSWORD_ENCODER.encode("password123"))
                .authorities(ApplicationUserRole.ADMIN.getGrantedAuthorities())
              //  .roles(ApplicationUserRole.ADMIN.name())
                .build();

        UserDetails tom = User.builder()
                .username("tom")
                .password(PASSWORD_ENCODER.encode("password123"))
                .authorities(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities())
               // .roles(ApplicationUserRole.ADMINTRAINEE.name())
                .build();

        return new InMemoryUserDetailsManager(annasmith,linda,tom);

    }
*/


    @Autowired
    public void authenticationManagerBuilder(AuthenticationManagerBuilder auth) throws Exception {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(PASSWORD_ENCODER);
        provider.setUserDetailsService(applicationUserService);
        auth.authenticationProvider(provider);
    }
}
