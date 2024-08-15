package org.adaschool.api.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.adaschool.api.exception.TokenExpiredException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import static org.adaschool.api.utils.Constants.CLAIMS_ROLES_KEY;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

class JwtRequestFilterTest {

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private FilterChain filterChain;

    @Mock
    private SecurityContext securityContext;

    @InjectMocks
    private JwtRequestFilter jwtRequestFilter;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        SecurityContextHolder.setContext(securityContext);
    }

    @Test
    void shouldAuthenticateWithValidToken() throws ServletException, IOException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        String token = "Bearer validToken";
        request.addHeader("Authorization", token);

        Claims claims = mock(Claims.class);
        when(claims.getSubject()).thenReturn("user");
        when(claims.get(CLAIMS_ROLES_KEY, List.class)).thenReturn(new ArrayList<>());
        when(jwtUtil.extractAndVerifyClaims("validToken")).thenReturn(claims);
        Method doFilterInternal = JwtRequestFilter.class.getDeclaredMethod("doFilterInternal", HttpServletRequest.class, HttpServletResponse.class, FilterChain.class);
        doFilterInternal.setAccessible(true);
        doFilterInternal.invoke(jwtRequestFilter, request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verify(securityContext).setAuthentication(any());
    }

    @Test
    void shouldThrowExceptionWithExpiredToken() throws ServletException, IOException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        String token = "Bearer expiredToken";
        request.addHeader("Authorization", token);

        when(jwtUtil.extractAndVerifyClaims("expiredToken")).thenThrow(new ExpiredJwtException(null, null, "Token expired"));

        Method doFilterInternal = JwtRequestFilter.class.getDeclaredMethod("doFilterInternal", HttpServletRequest.class, HttpServletResponse.class, FilterChain.class);
        doFilterInternal.setAccessible(true);
        try {
            doFilterInternal.invoke(jwtRequestFilter, request, response, filterChain);
        } catch (InvocationTargetException e) {
            assertTrue(e.getCause() instanceof TokenExpiredException);
        }
        verify(filterChain, never()).doFilter(request, response);
        verify(securityContext, never()).setAuthentication(any());
    }

    @Test
    void shouldContinueChainWithNoAuthorizationHeader() throws ServletException, IOException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        Method doFilterInternal = JwtRequestFilter.class.getDeclaredMethod("doFilterInternal", HttpServletRequest.class, HttpServletResponse.class, FilterChain.class);
        doFilterInternal.setAccessible(true);
        doFilterInternal.invoke(jwtRequestFilter, request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verify(securityContext, never()).setAuthentication(any());
    }
}