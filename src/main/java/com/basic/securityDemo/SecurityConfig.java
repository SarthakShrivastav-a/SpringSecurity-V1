package com.basic.securityDemo;

import com.basic.securityDemo.jwt.AuthEntryPointJwt;
import com.basic.securityDemo.jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.http.UserDetailsServiceFactoryBean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    DataSource dataSource;

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }


    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(); // encode the password
    }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> requests.requestMatchers("/h2-console/**").permitAll() //requestMatchers well as the name suggests matches requests and then performs action it.
                .requestMatchers("/signin").permitAll()
                .anyRequest().authenticated());
        http.sessionManagement(session->
                session.sessionCreationPolicy(
                        SessionCreationPolicy.STATELESS)
        );
        http.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler));
        //http.formLogin(withDefaults());
//        http.httpBasic(withDefaults());
        http.headers(headers->
                headers.frameOptions(HeadersConfigurer.FrameOptionsConfig:: sameOrigin)); //if frames are blocked in the frontend
        http.csrf(csrf->csrf.disable());//we gotta disble csrf as we are using stateless sessionManagement
        /*
        * Cross-Site Request Forgery (CSRF) is a type of security vulnerability
        * that allows an attacker to perform actions on behalf of an authenticated user without their consent.
        * To mitigate this risk, Spring Security enables CSRF protection by default for unsafe HTTP methods (like POST, PUT, DELETE).
        * */

        http.addFilterBefore(authenticationJwtTokenFilter(),
                UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }


    @Bean
    public CommandLineRunner initData(UserDetailsService userDetailsService) {
        return args -> {
            JdbcUserDetailsManager manager = (JdbcUserDetailsManager) userDetailsService;
            UserDetails user1 = User.withUsername("user1")
                    .password(passwordEncoder().encode("password1"))
                    .roles("USER")
                    .build();
            UserDetails admin = User.withUsername("admin")
                    //.password(passwordEncoder().encode("adminPass"))
                    .password(passwordEncoder().encode("adminPass"))
                    .roles("ADMIN")
                    .build();

            JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
            userDetailsManager.createUser(user1);
            userDetailsManager.createUser(admin);
        };
    }



//    @Bean
//    public UserDetailsService userDetailsService(){
//        UserDetails user1 = User.withUsername("user1")
//                .password(passwordEncoder().encode("admin1"))
//                .roles("USER")
//                .build();   //
//        UserDetails admin = User.withUsername("admin")
//                .password(passwordEncoder().encode("admin"))
//                .roles("ADMIN")
//                .build();


        /*
        * now To use this JDBC code, You first new to create table   for users authorizes and unique index
        * basically this is Schema defination!
        * go to github repo of springSecurity and under users.ddl you will find the schema
        * create table users(username varchar_ignorecase(50) not null primary key,password varchar_ignorecase(500) not null,enabled boolean not null);
        * create table authorities (username varchar_ignorecase(50) not null,authority varchar_ignorecase(50) not null,constraint fk_authorities_users foreign key(username) references users(username));
        * create unique index ix_auth_username on authorities (username,authority);
        * !!
        *
        * well this has to be stored in the file directory as h2 is inmemory database! Just store schema.sql under resources file and springboot will automatically handel it.
        * */
//        JdbcUserDetailsManager userDetailsManager= new JdbcUserDetailsManager(dataSource);
//
//        userDetailsManager.createUser(user1);
//        userDetailsManager.createUser(admin);   //now instead of creating a user in memory we are creating in db for future use.
//        return userDetailsManager;
        //return new InMemoryUserDetailsManager(user1,admin);// an obj of UserDetails is required
        @Bean
        public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
            return builder.getAuthenticationManager();
        }
}

