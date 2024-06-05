package com.nyaina.jwt.services;

import com.nyaina.jwt.models.User;
import com.nyaina.jwt.repositories.UserRepository;
import com.nyaina.jwt.utils.JwtUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class UserServiceTest {
    @InjectMocks
    private UserService service;
    @Mock
    private UserRepository repository;
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private JwtUtils jwtUtils;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void shouldSaveUSerWithSuccess() {
        //Given
        var givenUser = User.builder()
                .id(1)
                .username("Ny Aina")
                .password("hahaha")
                .build();

        var savedUser = User.builder()
                .id(1)
                .username("Ny Aina")
                .password("hahaha")
                .build();
        //Mock the calls
        when(repository.save(givenUser)).thenReturn(savedUser);
        //When
        var user = service.save(givenUser);
        //Then
        assertEquals(givenUser.getId(), user.getId());
        assertEquals(givenUser.getUsername(), user.getUsername());
        assertEquals(givenUser.getPassword(), user.getPassword());
        verify(repository, times(1)).save(givenUser);
    }
    @Test
    public void authenticationIsWorkingWell() {
        // Given
        User user = new User();
        user.setUsername("testuser");
        user.setPassword("testpassword");

        Authentication authentication = mock(Authentication.class);
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);

        UserDetails userDetails = mock(UserDetails.class);
        when(authentication.getPrincipal()).thenReturn(userDetails);

        String expectedJwt = "jwt-token";
        when(jwtUtils.generateJwtToken(authentication)).thenReturn(expectedJwt);

        // When
        UserDetails result = service.authenticateUser(user);
        // Then
        verify(authenticationManager, times(1)).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(jwtUtils, times(1)).generateJwtToken(authentication);
        assertEquals(userDetails, result);
    }
}