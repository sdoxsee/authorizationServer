package com.mycompany.myapp.web.rest;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.codahale.metrics.annotation.Timed;
import com.mycompany.myapp.domain.Authority;
import com.mycompany.myapp.domain.PersistentToken;
import com.mycompany.myapp.domain.User;
import com.mycompany.myapp.repository.PersistentTokenRepository;
import com.mycompany.myapp.repository.UserRepository;
import com.mycompany.myapp.security.SecurityUtils;
import com.mycompany.myapp.service.MailService;
import com.mycompany.myapp.service.UserService;
import com.mycompany.myapp.web.rest.dto.UserDTO;

/**
 * REST controller for managing the current user's account.
 */
@RestController
@RequestMapping("/api")
public class AccountResource {

    private final Logger log = LoggerFactory.getLogger(AccountResource.class);

    @Inject
    private UserRepository userRepository;

    @Inject
    private UserService userService;

    @Inject
    private PersistentTokenRepository persistentTokenRepository;

    @Inject
    private MailService mailService;

    /**
     * POST  /register -> register the user.
     */
    @RequestMapping(value = "/register",
            method = RequestMethod.POST,
            produces = MediaType.TEXT_PLAIN_VALUE)
    @Timed
    public ResponseEntity<?> registerAccount(@Valid @RequestBody UserDTO userDTO, HttpServletRequest request) {
        return userRepository.findOneByLogin(userDTO.getLogin())
            .map(user -> new ResponseEntity<>("login already in use", HttpStatus.BAD_REQUEST))
            .orElseGet(() -> userRepository.findOneByEmail(userDTO.getEmail())
                .map(user -> new ResponseEntity<>("e-mail address already in use", HttpStatus.BAD_REQUEST))
                .orElseGet(() -> {
                    User user = userService.createUserInformation(userDTO.getLogin(), userDTO.getPassword(),
                    userDTO.getFirstName(), userDTO.getLastName(), userDTO.getEmail().toLowerCase(),
                    userDTO.getLangKey());
                    String baseUrl = request.getScheme() + // "http"
                    "://" +                                // "://"
                    request.getServerName() +              // "myhost"
                    ":" +                                  // ":"
                    request.getServerPort();               // "80"

                    mailService.sendActivationEmail(user, baseUrl);
                    return new ResponseEntity<>(HttpStatus.CREATED);
                })
        );
    }
    /**
     * GET  /activate -> activate the registered user.
     */
    @RequestMapping(value = "/activate",
            method = RequestMethod.GET,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @Timed
    public ResponseEntity<String> activateAccount(@RequestParam(value = "key") String key) {
        return Optional.ofNullable(userService.activateRegistration(key))
            .map(user -> new ResponseEntity<String>(HttpStatus.OK))
            .orElse(new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR));
    }

    /**
     * GET  /authenticate -> check if the user is authenticated, and return its login.
     */
    @RequestMapping(value = "/authenticate",
            method = RequestMethod.GET,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @Timed
    public String isAuthenticated(HttpServletRequest request) {
        log.debug("REST request to check if the current user is authenticated");
        return request.getRemoteUser();
    }

    /**
     * GET  /account -> get the current user.
     */
    @RequestMapping(value = "/account",
            method = RequestMethod.GET,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @Timed
    public ResponseEntity<UserDTO> getAccount() {
        return Optional.ofNullable(userService.getUserWithAuthorities())
            .map(user -> new ResponseEntity<>(
                new UserDTO(
                    user.getLogin(),
                    null,
                    user.getFirstName(),
                    user.getLastName(),
                    user.getEmail(),
                    user.getLangKey(),
                    user.getAuthorities().stream().map(Authority::getName).collect(Collectors.toList())),
                HttpStatus.OK))
            .orElse(new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR));
    }

    /**
     * POST  /account -> update the current user information.
     */
    @RequestMapping(value = "/account",
            method = RequestMethod.POST,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @Timed
    public ResponseEntity<String> saveAccount(@RequestBody UserDTO userDTO) {
        return userRepository
            .findOneByLogin(userDTO.getLogin())
            .filter(u -> u.getLogin().equals(SecurityUtils.getCurrentLogin()))
            .map(u -> {
                userService.updateUserInformation(userDTO.getFirstName(), userDTO.getLastName(), userDTO.getEmail());
                return new ResponseEntity<String>(HttpStatus.OK);
            })
            .orElseGet(() -> new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR));
    }

    /**
     * POST  /change_password -> changes the current user's password
     */
    @RequestMapping(value = "/account/change_password",
            method = RequestMethod.POST,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @Timed
    public ResponseEntity<?> changePassword(@RequestBody String password) {
        if (StringUtils.isEmpty(password)) {
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        }
        userService.changePassword(password);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    /**
     * GET  /account/sessions -> get the current open sessions.
     */
    @RequestMapping(value = "/account/sessions",
            method = RequestMethod.GET,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @Timed
    public ResponseEntity<List<PersistentToken>> getCurrentSessions() {
        return userRepository.findOneByLogin(SecurityUtils.getCurrentLogin())
            .map(user -> new ResponseEntity<>(
                persistentTokenRepository.findByUser(user),
                HttpStatus.OK))
            .orElse(new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR));
    }

    /**
     * DELETE  /account/sessions?series={series} -> invalidate an existing session.
     *
     * - You can only delete your own sessions, not any other user's session
     * - If you delete one of your existing sessions, and that you are currently logged in on that session, you will
     *   still be able to use that session, until you quit your browser: it does not work in real time (there is
     *   no API for that), it only removes the "remember me" cookie
     * - This is also true if you invalidate your current session: you will still be able to use it until you close
     *   your browser or that the session times out. But automatic login (the "remember me" cookie) will not work
     *   anymore.
     *   There is an API to invalidate the current session, but there is no API to check which session uses which
     *   cookie.
     */
    @RequestMapping(value = "/account/sessions/{series}",
            method = RequestMethod.DELETE)
    @Timed
    public void invalidateSession(@PathVariable String series) throws UnsupportedEncodingException {
        String decodedSeries = URLDecoder.decode(series, "UTF-8");
        userRepository.findOneByLogin(SecurityUtils.getCurrentLogin()).ifPresent(u -> {
            persistentTokenRepository.findByUser(u).stream()
                .filter(persistentToken -> StringUtils.equals(persistentToken.getSeries(), decodedSeries))
                .findAny().ifPresent(t -> persistentTokenRepository.delete(decodedSeries));
        });
    }

    /**
     * GET  /account/token -> get the token for current open sessions.
     */
    @RequestMapping(value = "/account/token",
            method = RequestMethod.GET,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @Timed
    public @ResponseBody String getToken() {
		return getToken(SecurityUtils.getCurrentLogin());
    }

    private String getToken(String currentLogin) {
//    	Optional<User> user = userRepository.findOneByLogin(currentLogin);
    	String jwtUserToken = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxLjEiLCJhdWQiOlsid2VBcGkiXSwidXNlcl9uYW1lIjoidXNlciIsInNjb3BlIjpbInJlYWQiLCJ3cml0ZSJdLCJpc3MiOiJwZSIsImV4cCI6MTQyNjE1OTIxOCwiaWF0IjoxNDI0MzU5MjE4LCJhdXRob3JpdGllcyI6WyJST0xFX1VTRVIiXSwianRpIjoiOWEwOTYxN2QtYjkzOC00ZGQyLThiYWEtYmE1MTI1N2IxNDc5IiwiY2xpZW50X2lkIjoid2VhcHAifQ.KeX4P2jIbf7dhuaq-b_k_vo9B7DqM3dC5VHkqaMh0yRWbDpLWcJj4RQg_I6tXsTzDjgYTA8Atq8myQ-ODVZB5-4jfTsab0iYy5XmfeGrz7jNwZDKQLbYY3PxP6Yvl1Da7IAmxhOUHlJlYns7z4-0yzZUhvshxJroGjFGhmj2vhqorwStlRZgqxAy5ajTZXBKdWURPDdWiTUKIYCYJw8Xe11RSLjWgquxBjuI3s5_-PfqMtX6UK87M6rpO4hpRdKKpAw-WHp5Sp0wbcqN9K8_Cuq4hoMlAa0N3PEkjhXdGMkHLKGHoR9UApGHjB0J0rN9TT2xS_Bbdt5XsAjwp6goOg";
        String jwtAdminToken = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxLjEiLCJhdWQiOlsid2VBcGkiXSwidXNlcl9uYW1lIjoiYWRtaW4iLCJzY29wZSI6WyJyZWFkIiwid3JpdGUiXSwiaXNzIjoicGUiLCJleHAiOjE0MjYxNTk0MTQsImlhdCI6MTQyNDM1OTQxNCwiYXV0aG9yaXRpZXMiOlsiUk9MRV9BRE1JTiIsIlJPTEVfVVNFUiJdLCJqdGkiOiI3NzUxNjM2Yi1lMGY0LTRmNWEtYWJmNy03NTMzNjUzZDJmYjIiLCJjbGllbnRfaWQiOiJ3ZWFwcCJ9.cV9GOgF-n9Ma6P1Zeh9l_i3Poha26orwebYnAFZAo91Q0y4gKqOEY3mVYkA6FkwLKCh93YvZY8-NMb9EORaVWLZsS7gdoLerGs1OdQhKrUJ7dEn0Fsc3R-lCr4YdsOEmZGuBebuowwvevaMd3SeVlKCbdVRQfpkzFuKWRA36lulw2RUdi3YwdjbQOTX00U7QaQWOoFbbj48C7OPtyHiSzFTZ7rxiqdhrcXzsWZBZ9ZbWVELhutgXarUZfTBypsYRreuYOksvhnhVBPxGXN9tM2yr-mgCrTexoYTZuErwQEjUxxfTT0OQBKBYqb-KGs5LdFHT3rYXMQFGuZI7i2QTtg";
        String token = "{\"token\":\"";
        if (StringUtils.equals(currentLogin, "user")) {
        	token += jwtUserToken;
        } else if (StringUtils.equals(currentLogin, "admin")) {
        	token += jwtAdminToken;
        } else {
        	throw new IllegalStateException("login must be admin or user for now");
        }
      log.debug(token);
    	return token + "\"}";
    }
}
