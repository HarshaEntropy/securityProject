package com.imaginnovate.securityOAuth.entity;

import com.imaginnovate.securityOAuth.dto.UserCreationDTO;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDate;
import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "USERS")
public class User {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer id;

	@NonNull
	@Column(unique = true)
	private String username;
	@NonNull
	private String password;

	@Singular
	@ManyToMany(cascade = CascadeType.MERGE, fetch = FetchType.EAGER)
	@JoinTable(name = "users_authorities", joinColumns = {
			@JoinColumn(name = "USERS_ID", referencedColumnName = "ID") }, inverseJoinColumns = {
					@JoinColumn(name = "AUTHORITIES_ID", referencedColumnName = "ID") })
	private Set<Authority> authorities;

	@Builder.Default
	private Boolean accountNonExpired = true;
	@Builder.Default
	private Boolean accountNonLocked = true;
	@Builder.Default
	private Boolean credentialsNonExpired = true;
	@Builder.Default
	private Boolean enabled = true;

	private String firstName;
	private String lastName;
	private String emailAddress;
	private LocalDate birthdate;

	public User(UserCreationDTO userCreationDTO) {
		this.username = userCreationDTO.getUsername();
		this.password = userCreationDTO.getPassword();
		this.firstName = userCreationDTO.getFirstName();
		this.lastName = userCreationDTO.getLastName();
		this.emailAddress = userCreationDTO.getEmailAddress();
		this.birthdate = userCreationDTO.getBirthdate();
		this.accountNonExpired = true;  // Set default values
		this.accountNonLocked = true;
		this.credentialsNonExpired = true;
		this.enabled = true;
	}
}
