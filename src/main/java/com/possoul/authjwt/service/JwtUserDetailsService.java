package com.possoul.authjwt.service;


import com.possoul.authjwt.managers.PrincipalUser;
import com.possoul.authjwt.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class JwtUserDetailsService implements UserDetailsService {

    @Autowired
    PasswordEncoder encoder;

    List<User> userList = new ArrayList<>();

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = findByUsername(username);
        if (user == null){
            throw new UsernameNotFoundException("User not found with username: " + username);
        }
        return new PrincipalUser(user);
    }

    public User findByUsername(String username){
        return userList.stream().filter(u -> u.getUsername().equals(username)).
                findAny().orElse(null);
    }

    public void addUser(User user){
        user.setPassword(encoder.encode(user.getPassword()));
        userList.add(user);
    }
}