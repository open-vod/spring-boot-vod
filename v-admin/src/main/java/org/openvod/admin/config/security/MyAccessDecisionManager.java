package org.openvod.admin.config.security;

import com.google.common.collect.Sets;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.FilterInvocation;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Set;

@Slf4j
@Component
public class MyAccessDecisionManager implements AccessDecisionManager {

  private Set<String> publicUrls = Sets.newHashSet();

  public MyAccessDecisionManager() {
    publicUrls.add("/menus/get");
  }

  /**
   * 决定当前的role是否和访问对应资源的role相匹配
   *
   * @param authentication
   * @param o
   * @param collection
   * @throws AccessDeniedException
   * @throws InsufficientAuthenticationException
   */
  @Override
  public void decide(Authentication authentication, Object o, Collection<ConfigAttribute> collection) throws AccessDeniedException, InsufficientAuthenticationException {
    String requestUrl = ((FilterInvocation) o).getRequestUrl();
    Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
    for (ConfigAttribute configAttribute : collection) {
      String needRole = configAttribute.getAttribute();
//      if (FAKE_LOGIN_ROLE.equals(needRole)) {
//        if (authentication instanceof AnonymousAuthenticationToken) {
//          throw new AccessDeniedException("尚未登录，请登录!");
//        } else {
//          return;
////          if (publicUrls.contains(requestUrl)) {
////            return;
////          }
//        }
//      }
      for (GrantedAuthority authority : authorities) {
        if (authority.getAuthority().equals(needRole)) {
          return;
        }
      }
    }
    log.warn("current_role:{} need_role:{} url: {}", authorities.toString(), collection, requestUrl);
    throw new AccessDeniedException("权限不足，请联系管理员!");
  }

  @Override
  public boolean supports(ConfigAttribute configAttribute) {
    return true;
  }

  @Override
  public boolean supports(Class<?> aClass) {
    return true;
  }
}
