package com.paypal.jwtauthservice.repository;

import com.paypal.jwtauthservice.pojo.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {
    Optional<User>findByEmail(String email);
}
