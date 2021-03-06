package org.openvod.admin.config.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Maps;
import lombok.extern.slf4j.Slf4j;
import org.openvod.admin.entity.AdminUser;
import org.openvod.admin.service.AdminUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.ConcurrentSessionControlAuthenticationStrategy;
import org.springframework.security.web.session.ConcurrentSessionFilter;

import javax.servlet.http.HttpServletResponse;

@Slf4j
@Configuration
public class MySecurityConfig extends WebSecurityConfigurerAdapter {
  public static final String ENCODING = "UTF-8";
  public static final String LOGIN_URL = "/user/login";
  public static final String LOGIN_OUT_URL = "/user/logout";
  @Autowired
  private AdminUserService adminUserService;
  @Autowired
  private MyFilterInvocationSecurityMetadataSource myFilterInvocationSecurityMetadataSource;
  @Autowired
  private MyAccessDecisionManager myAccessDecisionManager;
  @Autowired
  private ObjectMapper objectMapper;

  @Override
  public void configure(WebSecurity web) throws Exception {
    web.ignoring().antMatchers("/css/**", "/js/**", "/index.html", "/img/**", "/fonts/**", "/favicon.ico", "/druid/**")
      .antMatchers("/swagger-ui.html", "/swagger-resources/**", "/webjars/**", "/v2/api-docs", "/doc.html")
      .antMatchers("/static/**")
      .antMatchers("/actuator/**/*");
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(adminUserService).passwordEncoder(new PasswordEncoder() {
      @Override
      public String encode(CharSequence charSequence) {
        return charSequence.toString();
      }

      @Override
      public boolean matches(CharSequence charSequence, String s) {
        return charSequence.equals(s);
      }
    });
  }

  @Bean
  MyAuthenticationFilter myAuthenticationFilter() throws Exception {
    MyAuthenticationFilter loginFilter = new MyAuthenticationFilter();
    loginFilter.setAuthenticationSuccessHandler((request, response, authentication) -> {
      response.setContentType(MediaType.APPLICATION_JSON_VALUE);
      response.setCharacterEncoding(ENCODING);
      AdminUser adminUser = (AdminUser) authentication.getPrincipal();
      objectMapper.writeValue(response.getOutputStream(), adminUser);
      log.info("user[{}] login in", adminUser.getUsername());
    });
    loginFilter.setAuthenticationFailureHandler((request, response, exception) -> {
      response.setContentType(MediaType.APPLICATION_JSON_VALUE);
      response.setCharacterEncoding(ENCODING);
      objectMapper.writeValue(response.getOutputStream(), ImmutableMap.of("message", exception.getMessage()));
    });
    loginFilter.setAuthenticationManager(authenticationManagerBean());
    loginFilter.setFilterProcessesUrl(LOGIN_URL);
    ConcurrentSessionControlAuthenticationStrategy sessionStrategy = new ConcurrentSessionControlAuthenticationStrategy(sessionRegistry());
    sessionStrategy.setMaximumSessions(1);
    loginFilter.setSessionAuthenticationStrategy(sessionStrategy);
    return loginFilter;
  }

  @Bean
  SessionRegistryImpl sessionRegistry() {
    return new SessionRegistryImpl();
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
      .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
        @Override
        public <O extends FilterSecurityInterceptor> O postProcess(O object) {
          object.setAccessDecisionManager(myAccessDecisionManager);
          object.setSecurityMetadataSource(myFilterInvocationSecurityMetadataSource);
          return object;
        }
      })
      .and()
      .logout()
      .logoutUrl(LOGIN_OUT_URL)
      .logoutSuccessHandler((request, response, authentication) -> {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(ENCODING);
        objectMapper.writeValue(response.getOutputStream(), Maps.newHashMap());
      })
      .permitAll()
      .and()
      .csrf().disable().exceptionHandling()
      //?????????????????????????????????????????????????????????
      .authenticationEntryPoint((req, resp, authException) -> {
        resp.setContentType(MediaType.APPLICATION_JSON_VALUE);
        resp.setCharacterEncoding(ENCODING);
        objectMapper.writeValue(resp.getWriter(), ImmutableMap.of("message", "????????????"));
      });
    http.addFilterAt(new ConcurrentSessionFilter(sessionRegistry(), event -> {
      HttpServletResponse resp = event.getResponse();
      resp.setContentType(MediaType.APPLICATION_JSON_VALUE);
      resp.setCharacterEncoding(ENCODING);
      objectMapper.writeValue(resp.getWriter(), ImmutableMap.of("message", "???????????????????????????"));
    }), ConcurrentSessionFilter.class);
    http.addFilterAt(myAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
  }
}
