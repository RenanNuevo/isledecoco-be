package com.abelium.inatrace.security.configuration;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;


@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(
    securedEnabled = true,
    jsr250Enabled = true,
    prePostEnabled = true
)
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Value("${cors.allowed-origins}")
    private List<String> allowedOrigins;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public TokenAuthenticationFilter tokenAuthenticationFilter() {
        return new TokenAuthenticationFilter();
    }
    
    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
        
    private static String[] swaggerExceptions = new String[] {
        "/v2/api-docs",
        "/swagger-resources",
        "/swagger-resources/**",
        "/configuration/ui",
        "/configuration/security",
        "/swagger-ui.html",
        "/webjars/**"
    };

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        CorsConfiguration corsConfig = new CorsConfiguration();
        corsConfig.setAllowedOrigins(allowedOrigins);
        corsConfig.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        corsConfig.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Requested-With", "accept", "Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"));
        corsConfig.setExposedHeaders(Arrays.asList("Authorization")); // Add the headers you want to expose
        corsConfig.setAllowCredentials(true); // Set it to true if your frontend sends credentials like cookies

        // Uncomment the line below if you want to allow all origins, headers, and methods by default
        corsConfig.applyPermitDefaultValues();

        http.cors().configurationSource(request -> corsConfig)
            .and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
            .csrf().disable()
            .formLogin().disable()
            .httpBasic().disable()
            .exceptionHandling().authenticationEntryPoint(new RestAuthenticationEntryPoint()).and()
            //.and().requestMatchers().antMatchers("/")
            .authorizeRequests()
                .antMatchers("/api/public/**", 
                        "/api/user/login",
                        "/api/user/refresh_authentication",
                        "/api/user/register",
                        "/api/user/request_reset_password",
                        "/api/user/reset_password",
                        "/api/user/confirm_email").permitAll()
                .antMatchers(swaggerExceptions).permitAll()
                .anyRequest().authenticated();        
        http.addFilterBefore(tokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}