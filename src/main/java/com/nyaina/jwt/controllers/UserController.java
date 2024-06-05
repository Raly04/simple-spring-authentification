package com.nyaina.jwt.controllers;

import com.nyaina.jwt.models.User;
import com.nyaina.jwt.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

@RequiredArgsConstructor
@Controller
@RequestMapping("/user")
public class UserController {
    private final UserService service;

    @PostMapping("/authenticate")
    public ResponseEntity<?> authenticate(@RequestBody User user) {
        try {
            return ResponseEntity.ok(service.authenticateUser(user));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(e.getMessage());
        }
    }

    @PostMapping("/create")
    public ResponseEntity<?> save(@RequestBody User user, UriComponentsBuilder builder) {
        try {
            var savedUser = service.save(user);
            URI location = builder
                    .path("/user/{id}")
                    .buildAndExpand(savedUser.getId())
                    .toUri();
            return ResponseEntity.created(location).body(savedUser);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(e.getMessage());
        }
    }
    @DeleteMapping("/delete/{id}")
    public ResponseEntity<?> delete (@PathVariable("id") Integer id) {
        try{
            service.deleteById(id);
            return ResponseEntity.noContent().build();
        }catch (Exception e){
            return ResponseEntity.internalServerError().body(e.getMessage());
        }
    }
}
