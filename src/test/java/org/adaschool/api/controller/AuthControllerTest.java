package org.adaschool.api.controller;


import jakarta.servlet.ServletException;
import org.adaschool.api.controller.auth.AuthController;
import org.adaschool.api.controller.auth.TokenDto;
import org.adaschool.api.data.user.UserEntity;
import org.adaschool.api.data.user.UserService;
import org.adaschool.api.exception.InvalidCredentialsException;
import org.adaschool.api.security.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Date;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
public class AuthControllerTest {

    private MockMvc mockMvc;

    @Mock
    private UserService userService;

    @Mock
    private JwtUtil jwtUtil;

    @InjectMocks
    private AuthController authController;

    @BeforeEach
    public void setup() {
        mockMvc = MockMvcBuilders.standaloneSetup(authController).build();
    }

    @Test
    public void loginSuccess() throws Exception {
        // Prepare data and mocks
        String username = "test@example.com";
        String password = "password";
        String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt());
        UserEntity userEntity = new UserEntity("Test", username, hashedPassword);
        TokenDto tokenDto = new TokenDto("fakeToken", new Date());

        given(userService.findByEmail(username)).willReturn(Optional.of(userEntity));
        when(jwtUtil.generateToken(username, userEntity.getRoles())).thenReturn(tokenDto);

        // Perform the request and assert
        mockMvc.perform(post("/api/v1/auth")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\", \"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("fakeToken"));
    }

    @Test
    public void loginFailure_InvalidCredentials() throws Exception {
        // Prepare data and mocks
        String username = "test@example.com";
        String password = "wrongpassword";

        given(userService.findByEmail(username)).willReturn(Optional.empty());

        try {
            mockMvc.perform(post("/api/v1/auth")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"username\":\"" + username + "\", \"password\":\"" + password + "\"}"))
                    .andExpect(status().isUnauthorized());
        } catch (ServletException e) {
            assertTrue(e.getCause() instanceof InvalidCredentialsException);
        }
    }
}
