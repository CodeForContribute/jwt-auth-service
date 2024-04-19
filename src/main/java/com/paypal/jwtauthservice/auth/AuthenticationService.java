package com.paypal.jwtauthservice.auth;

import com.paypal.jwtauthservice.config.JwtService;
import com.paypal.jwtauthservice.pojo.Role;
import com.paypal.jwtauthservice.pojo.User;
import com.paypal.jwtauthservice.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Log4j2
public class AuthenticationService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        User user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .pass(this.passwordEncoder.encode(request.getPassword()))
                .role(Role.ROLE_USER)
                .build();
        log.info("registering user {}", user);
        this.userRepository.save(user);
        String jwtToken = jwtService.generateToken(user);
        log.info("JWT token: {}", jwtToken);
        return AuthenticationResponse
                .builder()
                .accessToken(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
        log.info("fetch user details {}", authenticationRequest);
        User user = userRepository.findByEmail(authenticationRequest.getEmail()).orElseThrow();
        log.info("found user {}", user);
        log.info("authenticating user {}", user);
        this.authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getEmail(), authenticationRequest.getPassword()));
        String jwtToken = jwtService.generateToken(user);
        log.info("JWT token: {}", jwtToken);
        return AuthenticationResponse
                .builder()
                .accessToken(jwtToken)
                .build();
    }
}
