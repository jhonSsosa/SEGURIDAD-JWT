package org.adaschool.api.controller.auth;

import org.adaschool.api.data.user.UserEntity;
import org.adaschool.api.data.user.UserService;
import org.adaschool.api.exception.InvalidCredentialsException;
import org.adaschool.api.security.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

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
        Optional<UserEntity> userOptional = userService.findByEmail(loginDto.getUsername());
        if (userOptional.isPresent()) {
            UserEntity user = userOptional.get();
            if (BCrypt.checkpw(loginDto.getPassword(), user.getPasswordHash())) {
                TokenDto token = jwtUtil.generateToken(user.getEmail(), user.getRoles());
                return ResponseEntity.ok(token);
            }
        }
        throw new InvalidCredentialsException();
    }
}
