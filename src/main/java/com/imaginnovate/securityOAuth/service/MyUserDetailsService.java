package com.imaginnovate.securityOAuth.service;

import com.imaginnovate.securityOAuth.entity.User;
import com.imaginnovate.securityOAuth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import com.imaginnovate.securityOAuth.model.MyUserDetails;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class MyUserDetailsService implements UserDetailsService {

	private final UserRepository userRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Optional<User> user = userRepository.findByUsername(username);
	    return user.map(MyUserDetails::new).orElseThrow(() -> new UsernameNotFoundException("User not found"));
	}

}
