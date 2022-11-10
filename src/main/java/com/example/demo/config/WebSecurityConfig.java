package com.example.demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.example.demo.service.AccountUserDetailsService;

@Configuration
@EnableWebSecurity // --- (1)
@EnableGlobalMethodSecurity(prePostEnabled = true) // 追記 --- (1) メソッド認可処理を有効化
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    AccountUserDetailsService userDetailsService;

    PasswordEncoder passwordEncoder() {
        //BCryptアルゴリズムを使用してパスワードのハッシュ化を行う
        return new BCryptPasswordEncoder(); // --- (2) BCryptアルゴリズムを使用
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // AuthenticationManagerBuilderに、実装したUserDetailsServiceを設定する
        auth.userDetailsService(userDetailsService)     // --- (3) 作成したUserDetailsServiceを設定
                .passwordEncoder(passwordEncoder());    // --- (2) パスワードのハッシュ化方法を指定(BCryptアルゴリズム)
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 認可の設定
        http.exceptionHandling()    // 追記
        		.accessDeniedPage("/accessDeniedPage")  // 追記 --- (2) アクセス拒否された時に遷移するパス
        		.and()                  // 追記
        		.authorizeRequests()
                .antMatchers("/loginForm").permitAll()  // --- (4) /loginFormは、全ユーザからのアクセスを許可
                .anyRequest().authenticated();          // --- (5) /loginForm以外は、認証を求める

        // ログイン設定
        http.formLogin()                                // --- (6) フォーム認証の有効化
                .loginPage("/loginForm")                // --- (7) ログインフォームを表示するパス
                .loginProcessingUrl("/authenticate")    // --- (8) フォーム認証処理のパス
                .usernameParameter("userName")          // --- (9) ユーザ名のリクエストパラメータ名
                .passwordParameter("password")          // --- (10) パスワードのリクエストパラメータ名
                .defaultSuccessUrl("/home")             // --- (11) 認証成功時に遷移するデフォルトのパス
                .failureUrl("/loginForm?error=true");   // --- (12) 認証失敗時に遷移するパス

        // ログアウト設定
        http.logout()
                .logoutSuccessUrl("/loginForm")         // --- (13) ログアウト成功時に遷移するパス
                .permitAll();                           // --- (14) 全ユーザに対してアクセスを許可
    }
}