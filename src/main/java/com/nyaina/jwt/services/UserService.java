package com.nyaina.jwt.services;

import com.nyaina.jwt.models.User;
import com.nyaina.jwt.repositories.UserRepository;
import com.nyaina.jwt.utils.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@RequiredArgsConstructor
@Service
public class UserService {
    private final AuthenticationManager authenticationManager;
    private final UserRepository repository;
    private final JwtUtils jwtUtils;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public Map<String,Object> authenticateUser(User user) {
        Map<String,Object> response = new HashMap<>();
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String jwt = jwtUtils.generateToken(userDetails);
        if(bCryptPasswordEncoder.matches(user.getPassword(),userDetails.getPassword())) {
            response.put("token",jwt);
            response.put("user",userDetails);
            return response;
        }
        else throw new BadCredentialsException("Incorrect password");
    }

    public User save(User user) {
        var encryptedPassword = bCryptPasswordEncoder.encode(user.getPassword());

        return repository.save(User.builder()
                        .password(encryptedPassword)
                        .username(user.getUsername())
                .build());
    }

    public void deleteById(Integer id) {
        repository.deleteById(id);
    }
}
