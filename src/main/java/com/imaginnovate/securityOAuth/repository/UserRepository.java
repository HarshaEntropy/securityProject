package com.imaginnovate.securityOAuth.repository;

import com.imaginnovate.securityOAuth.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {

	Optional<User> findByUsername(String username);

	Page<User> findByUsernameContainingOrFirstNameContainingOrLastNameContaining(
			String username, String firstName, String lastName, Pageable pageable);

}
