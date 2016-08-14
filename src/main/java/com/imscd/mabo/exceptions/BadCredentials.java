package com.imscd.mabo.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Created by csperandio on 15/07/2016.
 */
@ResponseStatus(value = HttpStatus.UNAUTHORIZED)
public class BadCredentials extends RuntimeException {
    public BadCredentials(String message) {
        super(message);
    }
}
