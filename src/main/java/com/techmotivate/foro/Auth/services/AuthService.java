package com.techmotivate.foro.Auth.services;

import com.techmotivate.foro.Auth.dto.AuthResponse;
import com.techmotivate.foro.Auth.dto.LoginRequest;
import com.techmotivate.foro.Auth.dto.RegisterRequest;
import com.techmotivate.foro.Auth.entity.User;
import com.techmotivate.foro.Auth.enums.Role;
import com.techmotivate.foro.Auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthResponse login(LoginRequest request) {
        if (request.getUsername().equals(userRepository.findByUsername(request.getUsername()).get().getUsername().toString())) {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
            UserDetails user = userRepository.findByUsername(request.getUsername()).orElseThrow();

            return AuthResponse.builder()
            .token(jwtService.getToken(user))
            .build();

        } else {
            throw new RuntimeException("Bad Password");
        }
    }

    public AuthResponse register(RegisterRequest request) {
        User user = User.builder()
        .username(request.getUsername())
        .firstName(request.getFirstName())
        .lastName(request.getLastName())
        .email(request.getEmail())
        .password(passwordEncoder.encode(request.getPassword()))
        .email(request.getEmail())
        .country(request.getCountry())
        .role(Role.USER)
        .build();
        userRepository.save(user);

        return AuthResponse.builder()
        .token(jwtService.getToken(user))
        .build();
    }

}
