package com.example;

import java.security.Principal;
import javax.servlet.Filter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@SpringBootApplication
@EnableOAuth2Client
@RestController
public class OAuth2Application extends WebSecurityConfigurerAdapter {

  @Autowired
  OAuth2ClientContext oAuth2ClientContext;

  @RequestMapping("/user")
  public Principal lookupUser(Principal user) {
    return user;
  }

  @Override
  protected void configure(HttpSecurity http)
      throws Exception {
    http.antMatcher("/**")
        .addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class)
        .authorizeRequests()
        .antMatchers("/", "/login**", "/webjars/**")
        .permitAll()
        .anyRequest()
        .authenticated();
  }

  private Filter ssoFilter() {
    OAuth2ClientAuthenticationProcessingFilter filter =
        new OAuth2ClientAuthenticationProcessingFilter("/login/linkedin");
    OAuth2RestTemplate template = new OAuth2RestTemplate(linkedin(), oAuth2ClientContext);
    filter.setRestTemplate(template);
    filter.setTokenServices(new UserInfoTokenServices(linkedinResource().getUserInfoUri(), linkedin().getClientId()));

    return filter;
  }

  @Bean
  @ConfigurationProperties("linkedin.client_partner_tutorial")
  OAuth2ProtectedResourceDetails linkedin() {
    return new AuthorizationCodeResourceDetails();
  }

  @Bean
  @ConfigurationProperties("linkedin.resource")
  ResourceServerProperties linkedinResource() {
    return new ResourceServerProperties();
  }

  @Bean
  public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
    FilterRegistrationBean bean = new FilterRegistrationBean();
    bean.setFilter(filter);
    bean.setOrder(-100);
    return bean;
  }

  public static void main(String[] args) {
    SpringApplication.run(OAuth2Application.class, args);
  }
}
