package de.demo.config;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
@EnableMethodSecurity
@EnableWebSecurity
public class WebAuthorizationSecurityConfig {

    @Autowired
    public de.demo.security.CustomAuthenticationProvider authenticationProvider;
    
    @Bean
    public AuthenticationManager authManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = 
            http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.authenticationProvider(authenticationProvider);
        return authenticationManagerBuilder.build();
    }
    
		@Bean                                                      
		public SecurityFilterChain apiFilterChain(HttpSecurity httpSecurity) throws Exception {
			httpSecurity
				.securityMatcher("/**")                                   
				.authorizeHttpRequests(authorize -> authorize
					.anyRequest().hasAnyRole("ADMIN","USER")
				)
				.httpBasic(withDefaults());
			return httpSecurity.build();
		}

//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//            .anyRequest()
//            .authenticated()
//            .and()
//            .httpBasic();
//        return http.build();
//    }
    
	  @Bean
	  SecurityFilterChain formLoginFilterChain(HttpSecurity httpSecurity) throws Exception {
		     	        
		  httpSecurity.authorizeHttpRequests() //
//          .requestMatchers("/").authenticated()
          .requestMatchers("/login").permitAll()
          .requestMatchers("/react").permitAll() //
          .requestMatchers(HttpMethod.POST, "/search").authenticated() //
          .requestMatchers(HttpMethod.GET, "/api/**").authenticated()//
          .requestMatchers("/admin").hasRole("ADMIN") //
          .requestMatchers("/h2-console").hasRole("ADMIN") //
          .requestMatchers(HttpMethod.POST, "/delete/**", "/new-video").authenticated() //
          .anyRequest().authenticated() //
	              .and() //
//	              .exceptionHandling().accessDeniedHandler(accessDeniedHandler())
	              .formLogin(withDefaults()) //
	              .httpBasic(withDefaults());
	    return httpSecurity.build();
	  }
	  
	  
//	   @Bean
//	    public AccessDeniedHandler accessDeniedHandler() {
//	        return new CustomAccessDeniedHandler();
//	    }

}
