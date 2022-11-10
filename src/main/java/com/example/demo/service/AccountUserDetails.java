package com.example.demo.service;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;

import com.example.demo.entity.MyUser;

public class AccountUserDetails implements UserDetails {
    private final MyUser myUser;

    public AccountUserDetails(MyUser myUser) {
        this.myUser = myUser;
    }

    public MyUser getUser() { // --- (1) Entityである MyUserを返却するメソッド
        return myUser;
    }

    public String getName() { // --- (2) nameを返却するメソッド
        return this.myUser.getName();
    }


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() { // --- (3) ユーザに与えられている権限リストを返却するメソッド
        return AuthorityUtils.createAuthorityList("ROLE_" + this.myUser.getRoleName());
    }

    @Override
    public String getPassword() { // --- (4) 登録されているパスワードを返却するメソッド
        return this.myUser.getPassword();
    }

    @Override
    public String getUsername() { // --- (5) ユーザ名を返却するメソッド
        return this.myUser.getUserName();
    }

    @Override
    public boolean isAccountNonExpired() { // --- (6) アカウントの有効期限の状態を判定するメソッド
        return true;
    }

    @Override
    public boolean isAccountNonLocked() { // --- (7) アカウントのロック状態を判定するメソッド
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() { // --- (8) 資格情報の有効期限の状態を判定するメソッド
        return true;
    }

    @Override
    public boolean isEnabled() { // --- (9) 有効なユーザかを判定するメソッド
        return true;
    }
}