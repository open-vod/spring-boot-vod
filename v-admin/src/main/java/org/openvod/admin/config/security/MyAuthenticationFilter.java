package org.openvod.admin.config.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.Optional;

@Slf4j
public class MyAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
//  @Autowired
//  private SessionRegistry sessionRegistry;
  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
    if (!request.getMethod().equals("POST")) {
      throw new AuthenticationServiceException(
        "Authentication method not supported: " + request.getMethod());
    }
    if(!StringUtils.containsIgnoreCase(request.getContentType(), MediaType.APPLICATION_JSON_VALUE)) {
      throw new AuthenticationServiceException(
        "Authentication contentType not supported: " + request.getContentType());
    }
    try {
      Map<String, String> loginData = new ObjectMapper().readValue(request.getInputStream(), Map.class);
      String username = Optional.ofNullable(loginData.get("username")).orElseThrow(() -> new BadCredentialsException("缺少用户名"));
      String password = Optional.ofNullable(loginData.get("password")).orElseThrow(() -> new BadCredentialsException("缺少密码"));
      UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
      setDetails(request, authRequest);
//      sessionRegistry.registerNewSession(request.getSession(true).getId(), new SysUser());
      return this.getAuthenticationManager().authenticate(authRequest);
    } catch (IOException e) {
      log.error(e.getMessage());
    }
    return super.attemptAuthentication(request, response);
  }
}
