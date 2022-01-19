package com.holo2k.springjwt.security.services;

import javax.mail.MessagingException;
import java.io.FileNotFoundException;

public interface EmailService {

    void sendSimpleEmail(final String toAddress, final String subject, final String message);

    void sendEmailWithAttachment(final String toAddress, final String subject, final String message, final String attachment) throws MessagingException, FileNotFoundException;
}