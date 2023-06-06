package de.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.ldap.DefaultLdapUsernameToDnMapper;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.userdetails.LdapUserDetailsManager;

@Configuration
public class UserManagementSecurityConfig {

//	@Bean
//	CommandLineRunner initUsers(UserAccountRepository repository) {
//		return args -> {
//			repository.save(new UserAccount("alice", "pass", "USER"));
//			repository.save(new UserAccount("bob", "pass", "ROLE_USER"));
//			repository.save(new UserAccount("admin", "pass", "ADMIN"));
//		};
//	}


	  
	//  JDBC
//	  public UserDetailsService userDetailsService(DataSource dataSource) {
//		    String usersByUsernameQuery = "select username, password, enabled from spring.users where username = ?";
//		    String authsByUserQuery = "select username, authority from spring.authorities where username = ?";
//		    var userDetailsManager = new JdbcUserDetailsManager(dataSource);
//		    userDetailsManager.setUsersByUsernameQuery(usersByUsernameQuery);
//		    userDetailsManager.setAuthoritiesByUsernameQuery(authsByUserQuery);
//		    return userDetailsManager;
//
//		  }
	  
	  
	  
	  //LDAP
  
	    @Bean
	    public UserDetailsService userDetailsService() {
	        var cs = new DefaultSpringSecurityContextSource("ldap://127.0.0.1:33389/dc=springframework,dc=org");
	        cs.afterPropertiesSet();

	        LdapUserDetailsManager manager = new LdapUserDetailsManager(cs);
	        manager.setUsernameMapper(
	                new DefaultLdapUsernameToDnMapper("ou=groups", "uid"));
	        manager.setGroupSearchBase("ou=groups");
	        return manager;
	    }
	    
	    @Bean
	    public BCryptPasswordEncoder passwordEncoder() {
	    return new BCryptPasswordEncoder();
	    }

}
