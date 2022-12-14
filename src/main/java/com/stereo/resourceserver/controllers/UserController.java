package com.stereo.resourceserver.controllers;

import com.stereo.resourceserver.response.UserRest;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class UserController {

    @GetMapping("/status/check")
    public String status(){
        return "Working...";
    }

     /*will not work as in security config we have defined developer
    @Secured("ROLE_user")*/

     /*will work as in security config we have defined developer
    @Secured("ROLE_developer")*/

//    @PreAuthorize("hasRole('developer') or #id == #jwt.subject")
    @PreAuthorize("hasRole('developer') or #id == #jwt.subject")
    @DeleteMapping(path = "/{id}")
    public String deleteUser(@PathVariable String id, @AuthenticationPrincipal Jwt jwt){
        return "Deleted user with id: " + id + " and JWT subject " + jwt.getSubject();
    }

    @PostAuthorize("returnObject.userId == #jwt.subject")
    @GetMapping(path = "/{id}")
    public UserRest getUser(@PathVariable String id, @AuthenticationPrincipal Jwt jwt){
        return new UserRest("Rahul", "Pareek", "0349774e-7bfe-4249-99d9-7524de400");
    }

}
