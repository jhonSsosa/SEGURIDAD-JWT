package org.adaschool.api.controller.auth;

import org.adaschool.api.data.user.UserService;
import org.adaschool.api.security.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final UserService userService;

    private final JwtUtil jwtUtil;


    public AuthController(UserService userService, JwtUtil jwtUtil) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping
    public ResponseEntity<TokenDto> login(@RequestBody LoginDto loginDto) {
        return ResponseEntity.ok(null);
    }


}
