package org.adaschool.api.controller.user;

import jakarta.annotation.security.RolesAllowed;
import org.adaschool.api.data.user.RoleEnum;
import org.adaschool.api.data.user.UserEntity;
import org.adaschool.api.data.user.UserService;
import org.adaschool.api.exception.UserWithEmailAlreadyRegisteredException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

import static org.adaschool.api.utils.Constants.ADMIN_ROLE;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    public UserController(UserService userService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/{id}")
    public ResponseEntity<UserEntity> getUserById(@PathVariable String id) {
        return userService.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public ResponseEntity<UserEntity> createUser(@RequestBody UserDto userDto) {
        if (userService.findByEmail(userDto.getEmail()).isPresent()) {
            throw new UserWithEmailAlreadyRegisteredException();
        }
        UserEntity userEntity = new UserEntity(userDto.getName(), userDto.getEmail(), passwordEncoder.encode(userDto.getPassword()));
        return ResponseEntity.ok(userService.save(userEntity));
    }

    @RolesAllowed(ADMIN_ROLE)
    @DeleteMapping("/{id}")
    public ResponseEntity<Boolean> deleteUser(@PathVariable String id) {
        Optional<UserEntity> userOptional = userService.findById(id);
        if (userOptional.isPresent()) {
            userService.delete(userOptional.get());
            return ResponseEntity.ok(true);
        }
        return ResponseEntity.ok(false);
    }
}
