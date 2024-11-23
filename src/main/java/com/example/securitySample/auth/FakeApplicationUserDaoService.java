package com.example.securitySample.auth;

import com.example.securitySample.security.ApplicationUserRole;
import com.example.securitySample.student.StudentController;
import com.google.common.collect.Lists;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;
import java.util.Optional;


@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {

    private final PasswordEncoder PASSWORD_ENCODER;

    public FakeApplicationUserDaoService(PasswordEncoder password_encoder) {
        PASSWORD_ENCODER = password_encoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUSsers()
                .stream()
                .filter(applicationUser ->
                        username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUSsers() {
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
                new ApplicationUser(
                        "annasmith",
                        PASSWORD_ENCODER.encode("password"),
                        ApplicationUserRole.STUDENT.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true),
                new ApplicationUser(
                        "linda",
                        PASSWORD_ENCODER.encode("password123"),
                        ApplicationUserRole.ADMIN.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true),
                new ApplicationUser(
                        "tom",
                        PASSWORD_ENCODER.encode("password123"),
                        ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true)
        );

        return applicationUsers;
    }




}
