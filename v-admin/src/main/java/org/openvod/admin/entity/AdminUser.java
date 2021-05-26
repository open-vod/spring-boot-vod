package org.openvod.admin.entity;

import com.google.common.collect.Lists;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

public class AdminUser implements UserDetails {
  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return Lists.newArrayList(new SimpleGrantedAuthority("administrator"));
  }

  @Override
  public String getPassword() {
    return "vod";
  }

  @Override
  public String getUsername() {
    return "vod";
  }

  @Override
  public boolean isAccountNonExpired() {
    return false;
  }

  @Override
  public boolean isAccountNonLocked() {
    return false;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return false;
  }

  @Override
  public boolean isEnabled() {
    return false;
  }
}
