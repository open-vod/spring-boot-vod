package org.openvod.admin.config.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.Collection;

@Component
@Slf4j
public class MyFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

  public static final String FAKE_LOGIN_ROLE = "ROLE_LOGIN";
  public static final String ROLE_ANONYMOUS = "ROLE_ANONYMOUS";
  private static final String SEPARATOR = ",";

  public static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();

  /**
   * 决定当前url可以有哪些role可以访问
   *
   * @param o
   * @return
   * @throws IllegalArgumentException
   */
  @Override
  public Collection<ConfigAttribute> getAttributes(Object o) throws IllegalArgumentException {
    String requestUrl = ((FilterInvocation) o).getRequestUrl();
    System.out.println(requestUrl);
    return SecurityConfig.createList("administrator");
  }

  @Override
  public Collection<ConfigAttribute> getAllConfigAttributes() {
    return null;
  }

  @Override
  public boolean supports(Class<?> aClass) {
    return true;
  }
}
