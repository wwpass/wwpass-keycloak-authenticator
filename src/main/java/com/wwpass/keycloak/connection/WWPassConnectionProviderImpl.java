package com.wwpass.keycloak.connection;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.jboss.logging.Logger;

import org.keycloak.common.util.Base64;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.common.util.PemUtils;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

import com.wwpass.keycloak.ticket.WWPassTicket;

final class WWPassConnectionProviderImpl implements WWPassConnectionProvider {

    private static final byte[] WWPASS_CA_DER = {
            (byte) 0x30, (byte) 0x82, (byte) 0x06, (byte) 0x01, (byte) 0x30, (byte) 0x82,
            (byte) 0x03, (byte) 0xe9, (byte) 0xa0, (byte) 0x03, (byte) 0x02, (byte) 0x01,
            (byte) 0x02, (byte) 0x02, (byte) 0x09, (byte) 0x00, (byte) 0xde, (byte) 0xc9,
            (byte) 0x65, (byte) 0x49, (byte) 0x60, (byte) 0x94, (byte) 0x69, (byte) 0xf8,
            (byte) 0x30, (byte) 0x0d, (byte) 0x06, (byte) 0x09, (byte) 0x2a, (byte) 0x86,
            (byte) 0x48, (byte) 0x86, (byte) 0xf7, (byte) 0x0d, (byte) 0x01, (byte) 0x01,
            (byte) 0x0b, (byte) 0x05, (byte) 0x00, (byte) 0x30, (byte) 0x57, (byte) 0x31,
            (byte) 0x0b, (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x03, (byte) 0x55,
            (byte) 0x04, (byte) 0x06, (byte) 0x13, (byte) 0x02, (byte) 0x55, (byte) 0x53,
            (byte) 0x31, (byte) 0x1b, (byte) 0x30, (byte) 0x19, (byte) 0x06, (byte) 0x03,
            (byte) 0x55, (byte) 0x04, (byte) 0x0a, (byte) 0x13, (byte) 0x12, (byte) 0x57,
            (byte) 0x57, (byte) 0x50, (byte) 0x61, (byte) 0x73, (byte) 0x73, (byte) 0x20,
            (byte) 0x43, (byte) 0x6f, (byte) 0x72, (byte) 0x70, (byte) 0x6f, (byte) 0x72,
            (byte) 0x61, (byte) 0x74, (byte) 0x69, (byte) 0x6f, (byte) 0x6e, (byte) 0x31,
            (byte) 0x2b, (byte) 0x30, (byte) 0x29, (byte) 0x06, (byte) 0x03, (byte) 0x55,
            (byte) 0x04, (byte) 0x03, (byte) 0x13, (byte) 0x22, (byte) 0x57, (byte) 0x57,
            (byte) 0x50, (byte) 0x61, (byte) 0x73, (byte) 0x73, (byte) 0x20, (byte) 0x43,
            (byte) 0x6f, (byte) 0x72, (byte) 0x70, (byte) 0x6f, (byte) 0x72, (byte) 0x61,
            (byte) 0x74, (byte) 0x69, (byte) 0x6f, (byte) 0x6e, (byte) 0x20, (byte) 0x50,
            (byte) 0x72, (byte) 0x69, (byte) 0x6d, (byte) 0x61, (byte) 0x72, (byte) 0x79,
            (byte) 0x20, (byte) 0x52, (byte) 0x6f, (byte) 0x6f, (byte) 0x74, (byte) 0x20,
            (byte) 0x43, (byte) 0x41, (byte) 0x30, (byte) 0x22, (byte) 0x18, (byte) 0x0f,
            (byte) 0x32, (byte) 0x30, (byte) 0x31, (byte) 0x32, (byte) 0x31, (byte) 0x31,
            (byte) 0x32, (byte) 0x38, (byte) 0x30, (byte) 0x39, (byte) 0x30, (byte) 0x30,
            (byte) 0x30, (byte) 0x30, (byte) 0x5a, (byte) 0x18, (byte) 0x0f, (byte) 0x32,
            (byte) 0x30, (byte) 0x35, (byte) 0x32, (byte) 0x31, (byte) 0x31, (byte) 0x32,
            (byte) 0x38, (byte) 0x30, (byte) 0x38, (byte) 0x35, (byte) 0x39, (byte) 0x35,
            (byte) 0x39, (byte) 0x5a, (byte) 0x30, (byte) 0x57, (byte) 0x31, (byte) 0x0b,
            (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04,
            (byte) 0x06, (byte) 0x13, (byte) 0x02, (byte) 0x55, (byte) 0x53, (byte) 0x31,
            (byte) 0x1b, (byte) 0x30, (byte) 0x19, (byte) 0x06, (byte) 0x03, (byte) 0x55,
            (byte) 0x04, (byte) 0x0a, (byte) 0x13, (byte) 0x12, (byte) 0x57, (byte) 0x57,
            (byte) 0x50, (byte) 0x61, (byte) 0x73, (byte) 0x73, (byte) 0x20, (byte) 0x43,
            (byte) 0x6f, (byte) 0x72, (byte) 0x70, (byte) 0x6f, (byte) 0x72, (byte) 0x61,
            (byte) 0x74, (byte) 0x69, (byte) 0x6f, (byte) 0x6e, (byte) 0x31, (byte) 0x2b,
            (byte) 0x30, (byte) 0x29, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04,
            (byte) 0x03, (byte) 0x13, (byte) 0x22, (byte) 0x57, (byte) 0x57, (byte) 0x50,
            (byte) 0x61, (byte) 0x73, (byte) 0x73, (byte) 0x20, (byte) 0x43, (byte) 0x6f,
            (byte) 0x72, (byte) 0x70, (byte) 0x6f, (byte) 0x72, (byte) 0x61, (byte) 0x74,
            (byte) 0x69, (byte) 0x6f, (byte) 0x6e, (byte) 0x20, (byte) 0x50, (byte) 0x72,
            (byte) 0x69, (byte) 0x6d, (byte) 0x61, (byte) 0x72, (byte) 0x79, (byte) 0x20,
            (byte) 0x52, (byte) 0x6f, (byte) 0x6f, (byte) 0x74, (byte) 0x20, (byte) 0x43,
            (byte) 0x41, (byte) 0x30, (byte) 0x82, (byte) 0x02, (byte) 0x22, (byte) 0x30,
            (byte) 0x0d, (byte) 0x06, (byte) 0x09, (byte) 0x2a, (byte) 0x86, (byte) 0x48,
            (byte) 0x86, (byte) 0xf7, (byte) 0x0d, (byte) 0x01, (byte) 0x01, (byte) 0x01,
            (byte) 0x05, (byte) 0x00, (byte) 0x03, (byte) 0x82, (byte) 0x02, (byte) 0x0f,
            (byte) 0x00, (byte) 0x30, (byte) 0x82, (byte) 0x02, (byte) 0x0a, (byte) 0x02,
            (byte) 0x82, (byte) 0x02, (byte) 0x01, (byte) 0x00, (byte) 0xc9, (byte) 0x85,
            (byte) 0xa6, (byte) 0x5d, (byte) 0x56, (byte) 0x5f, (byte) 0xcd, (byte) 0x28,
            (byte) 0xb3, (byte) 0x28, (byte) 0x16, (byte) 0xc7, (byte) 0x86, (byte) 0x57,
            (byte) 0xf3, (byte) 0x11, (byte) 0xb2, (byte) 0x61, (byte) 0xf1, (byte) 0xf1,
            (byte) 0xf1, (byte) 0xca, (byte) 0x73, (byte) 0xdb, (byte) 0xd9, (byte) 0x79,
            (byte) 0xb3, (byte) 0xfe, (byte) 0xe6, (byte) 0x81, (byte) 0x02, (byte) 0x18,
            (byte) 0x0a, (byte) 0xb9, (byte) 0x94, (byte) 0x48, (byte) 0xb2, (byte) 0xbd,
            (byte) 0x2a, (byte) 0xd4, (byte) 0xab, (byte) 0xc8, (byte) 0x0d, (byte) 0x29,
            (byte) 0x9b, (byte) 0x3a, (byte) 0xce, (byte) 0x16, (byte) 0x4c, (byte) 0x8d,
            (byte) 0x06, (byte) 0xe4, (byte) 0xf4, (byte) 0x39, (byte) 0x4e, (byte) 0x6e,
            (byte) 0x70, (byte) 0x2b, (byte) 0xaf, (byte) 0xd9, (byte) 0x63, (byte) 0x60,
            (byte) 0x52, (byte) 0xb8, (byte) 0x89, (byte) 0x67, (byte) 0xbf, (byte) 0x1b,
            (byte) 0xf2, (byte) 0xc7, (byte) 0xa4, (byte) 0x5b, (byte) 0x5a, (byte) 0x17,
            (byte) 0xcb, (byte) 0x64, (byte) 0x17, (byte) 0x9d, (byte) 0xd6, (byte) 0x52,
            (byte) 0xb3, (byte) 0xe0, (byte) 0x80, (byte) 0xf9, (byte) 0x4a, (byte) 0x07,
            (byte) 0x17, (byte) 0x0d, (byte) 0x18, (byte) 0xa9, (byte) 0x31, (byte) 0x03,
            (byte) 0x3b, (byte) 0xae, (byte) 0x7d, (byte) 0xfd, (byte) 0x38, (byte) 0xe4,
            (byte) 0x36, (byte) 0xa9, (byte) 0x44, (byte) 0xe4, (byte) 0x73, (byte) 0x17,
            (byte) 0x75, (byte) 0x8b, (byte) 0xc8, (byte) 0x6f, (byte) 0xb8, (byte) 0xe1,
            (byte) 0x70, (byte) 0xe0, (byte) 0x31, (byte) 0x0b, (byte) 0xc8, (byte) 0x30,
            (byte) 0x00, (byte) 0x91, (byte) 0x60, (byte) 0x02, (byte) 0x44, (byte) 0x1b,
            (byte) 0xa1, (byte) 0xa3, (byte) 0x08, (byte) 0x92, (byte) 0xe5, (byte) 0xac,
            (byte) 0x02, (byte) 0x7a, (byte) 0x4e, (byte) 0xb4, (byte) 0xac, (byte) 0xeb,
            (byte) 0x9e, (byte) 0x45, (byte) 0x87, (byte) 0x1b, (byte) 0x3e, (byte) 0x39,
            (byte) 0xaa, (byte) 0x8c, (byte) 0x88, (byte) 0x0a, (byte) 0x3a, (byte) 0xb3,
            (byte) 0x7d, (byte) 0xe0, (byte) 0xdc, (byte) 0x37, (byte) 0x47, (byte) 0x61,
            (byte) 0xdc, (byte) 0x84, (byte) 0xcc, (byte) 0x1d, (byte) 0x7a, (byte) 0xd8,
            (byte) 0x8b, (byte) 0x09, (byte) 0x15, (byte) 0xab, (byte) 0x97, (byte) 0xc6,
            (byte) 0x5c, (byte) 0x73, (byte) 0xdb, (byte) 0xb8, (byte) 0x93, (byte) 0xdb,
            (byte) 0xb8, (byte) 0x13, (byte) 0x7e, (byte) 0xba, (byte) 0x79, (byte) 0xda,
            (byte) 0x91, (byte) 0xb2, (byte) 0xf7, (byte) 0x3a, (byte) 0x09, (byte) 0x37,
            (byte) 0xc8, (byte) 0xf9, (byte) 0xc4, (byte) 0x72, (byte) 0x6e, (byte) 0x98,
            (byte) 0x57, (byte) 0xe1, (byte) 0xeb, (byte) 0xc5, (byte) 0x0e, (byte) 0xd2,
            (byte) 0x2b, (byte) 0x2f, (byte) 0x37, (byte) 0xab, (byte) 0xad, (byte) 0x00,
            (byte) 0x6d, (byte) 0xdc, (byte) 0xbc, (byte) 0x7e, (byte) 0xdd, (byte) 0x11,
            (byte) 0xa5, (byte) 0x22, (byte) 0x5e, (byte) 0x52, (byte) 0x40, (byte) 0x63,
            (byte) 0x25, (byte) 0x5c, (byte) 0x22, (byte) 0x1e, (byte) 0xee, (byte) 0x32,
            (byte) 0xe2, (byte) 0x3e, (byte) 0x62, (byte) 0x28, (byte) 0x2d, (byte) 0x6d,
            (byte) 0x36, (byte) 0x0b, (byte) 0x55, (byte) 0xf2, (byte) 0xa1, (byte) 0x3d,
            (byte) 0x65, (byte) 0xfd, (byte) 0xa0, (byte) 0xe6, (byte) 0xf0, (byte) 0x07,
            (byte) 0xcc, (byte) 0xbd, (byte) 0xe8, (byte) 0x6e, (byte) 0xa9, (byte) 0xee,
            (byte) 0x20, (byte) 0xca, (byte) 0xfc, (byte) 0x26, (byte) 0x99, (byte) 0x96,
            (byte) 0xa7, (byte) 0x43, (byte) 0x2b, (byte) 0xad, (byte) 0x46, (byte) 0xbd,
            (byte) 0x8d, (byte) 0x83, (byte) 0xad, (byte) 0x29, (byte) 0x79, (byte) 0x36,
            (byte) 0x2e, (byte) 0x76, (byte) 0x67, (byte) 0x7f, (byte) 0x1b, (byte) 0xab,
            (byte) 0x27, (byte) 0xbe, (byte) 0x0d, (byte) 0x56, (byte) 0x4d, (byte) 0x91,
            (byte) 0x9a, (byte) 0xe3, (byte) 0x79, (byte) 0x23, (byte) 0xf1, (byte) 0xf4,
            (byte) 0x6b, (byte) 0xfb, (byte) 0x54, (byte) 0xac, (byte) 0x75, (byte) 0xad,
            (byte) 0x08, (byte) 0x4e, (byte) 0x69, (byte) 0x71, (byte) 0x53, (byte) 0x64,
            (byte) 0x6f, (byte) 0x7b, (byte) 0xe6, (byte) 0xa2, (byte) 0xa7, (byte) 0x85,
            (byte) 0xb1, (byte) 0xb4, (byte) 0xec, (byte) 0xd8, (byte) 0xa0, (byte) 0xc2,
            (byte) 0x32, (byte) 0xaf, (byte) 0xe0, (byte) 0xcd, (byte) 0x48, (byte) 0x47,
            (byte) 0x53, (byte) 0x7d, (byte) 0x65, (byte) 0xe1, (byte) 0x9a, (byte) 0xe5,
            (byte) 0xcf, (byte) 0xef, (byte) 0x43, (byte) 0x7c, (byte) 0x15, (byte) 0x31,
            (byte) 0x95, (byte) 0xbe, (byte) 0x5f, (byte) 0x35, (byte) 0x80, (byte) 0x79,
            (byte) 0x94, (byte) 0x5e, (byte) 0x05, (byte) 0x9d, (byte) 0x1f, (byte) 0xb9,
            (byte) 0xfe, (byte) 0x12, (byte) 0xa0, (byte) 0xa3, (byte) 0xbe, (byte) 0x7e,
            (byte) 0x39, (byte) 0xa3, (byte) 0x63, (byte) 0x89, (byte) 0x27, (byte) 0xe9,
            (byte) 0xf6, (byte) 0x04, (byte) 0xc7, (byte) 0xe9, (byte) 0x87, (byte) 0xc5,
            (byte) 0x0a, (byte) 0x94, (byte) 0xb4, (byte) 0x3a, (byte) 0x51, (byte) 0xe6,
            (byte) 0x2a, (byte) 0x1b, (byte) 0x11, (byte) 0x26, (byte) 0x54, (byte) 0x76,
            (byte) 0x68, (byte) 0x82, (byte) 0xa9, (byte) 0x4d, (byte) 0x41, (byte) 0x06,
            (byte) 0xf6, (byte) 0x18, (byte) 0xd2, (byte) 0x83, (byte) 0x73, (byte) 0xa1,
            (byte) 0xed, (byte) 0x79, (byte) 0x69, (byte) 0x24, (byte) 0x78, (byte) 0x56,
            (byte) 0xa2, (byte) 0x54, (byte) 0x10, (byte) 0xd8, (byte) 0x17, (byte) 0x8b,
            (byte) 0xfb, (byte) 0xed, (byte) 0xd4, (byte) 0x3b, (byte) 0x24, (byte) 0x4c,
            (byte) 0x4c, (byte) 0x34, (byte) 0x93, (byte) 0x67, (byte) 0x56, (byte) 0xc6,
            (byte) 0x6b, (byte) 0xdd, (byte) 0xa8, (byte) 0xcf, (byte) 0x99, (byte) 0xd2,
            (byte) 0xf9, (byte) 0x45, (byte) 0x2c, (byte) 0x13, (byte) 0x99, (byte) 0xe8,
            (byte) 0x51, (byte) 0x94, (byte) 0xa3, (byte) 0x2c, (byte) 0xcf, (byte) 0x8a,
            (byte) 0x6d, (byte) 0xa2, (byte) 0x63, (byte) 0x64, (byte) 0x60, (byte) 0xb1,
            (byte) 0xcc, (byte) 0xef, (byte) 0x72, (byte) 0xdb, (byte) 0x08, (byte) 0x85,
            (byte) 0x05, (byte) 0xb4, (byte) 0x52, (byte) 0x6e, (byte) 0x12, (byte) 0xf6,
            (byte) 0xcd, (byte) 0x7a, (byte) 0x54, (byte) 0x0f, (byte) 0x67, (byte) 0x4c,
            (byte) 0x07, (byte) 0x51, (byte) 0xb7, (byte) 0xd2, (byte) 0x36, (byte) 0x70,
            (byte) 0xca, (byte) 0xd8, (byte) 0xe7, (byte) 0xd7, (byte) 0x95, (byte) 0x40,
            (byte) 0x30, (byte) 0x43, (byte) 0x98, (byte) 0x8b, (byte) 0x30, (byte) 0x68,
            (byte) 0x1c, (byte) 0x4a, (byte) 0x76, (byte) 0x35, (byte) 0xff, (byte) 0x4f,
            (byte) 0x36, (byte) 0x1b, (byte) 0x03, (byte) 0x19, (byte) 0xad, (byte) 0xf6,
            (byte) 0x01, (byte) 0xca, (byte) 0x49, (byte) 0xd9, (byte) 0xad, (byte) 0x27,
            (byte) 0xf3, (byte) 0xda, (byte) 0x5b, (byte) 0x48, (byte) 0xe9, (byte) 0x6e,
            (byte) 0xca, (byte) 0xbf, (byte) 0xef, (byte) 0x13, (byte) 0x36, (byte) 0x23,
            (byte) 0x27, (byte) 0x60, (byte) 0xd9, (byte) 0xfd, (byte) 0x35, (byte) 0x90,
            (byte) 0x41, (byte) 0xbe, (byte) 0xee, (byte) 0xa6, (byte) 0x2d, (byte) 0x06,
            (byte) 0xda, (byte) 0x44, (byte) 0x57, (byte) 0xd7, (byte) 0xb5, (byte) 0x08,
            (byte) 0x67, (byte) 0x96, (byte) 0x5f, (byte) 0x86, (byte) 0x39, (byte) 0x81,
            (byte) 0x02, (byte) 0x03, (byte) 0x01, (byte) 0x00, (byte) 0x01, (byte) 0xa3,
            (byte) 0x81, (byte) 0xcb, (byte) 0x30, (byte) 0x81, (byte) 0xc8, (byte) 0x30,
            (byte) 0x1d, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1d, (byte) 0x0e,
            (byte) 0x04, (byte) 0x16, (byte) 0x04, (byte) 0x14, (byte) 0x6b, (byte) 0xbf,
            (byte) 0x1f, (byte) 0x86, (byte) 0xff, (byte) 0x82, (byte) 0x7f, (byte) 0x11,
            (byte) 0xcc, (byte) 0xbe, (byte) 0xd7, (byte) 0x28, (byte) 0x70, (byte) 0x53,
            (byte) 0xe8, (byte) 0xae, (byte) 0x01, (byte) 0x41, (byte) 0xc9, (byte) 0x7b,
            (byte) 0x30, (byte) 0x81, (byte) 0x88, (byte) 0x06, (byte) 0x03, (byte) 0x55,
            (byte) 0x1d, (byte) 0x23, (byte) 0x04, (byte) 0x81, (byte) 0x80, (byte) 0x30,
            (byte) 0x7e, (byte) 0x80, (byte) 0x14, (byte) 0x6b, (byte) 0xbf, (byte) 0x1f,
            (byte) 0x86, (byte) 0xff, (byte) 0x82, (byte) 0x7f, (byte) 0x11, (byte) 0xcc,
            (byte) 0xbe, (byte) 0xd7, (byte) 0x28, (byte) 0x70, (byte) 0x53, (byte) 0xe8,
            (byte) 0xae, (byte) 0x01, (byte) 0x41, (byte) 0xc9, (byte) 0x7b, (byte) 0xa1,
            (byte) 0x5b, (byte) 0xa4, (byte) 0x59, (byte) 0x30, (byte) 0x57, (byte) 0x31,
            (byte) 0x0b, (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x03, (byte) 0x55,
            (byte) 0x04, (byte) 0x06, (byte) 0x13, (byte) 0x02, (byte) 0x55, (byte) 0x53,
            (byte) 0x31, (byte) 0x1b, (byte) 0x30, (byte) 0x19, (byte) 0x06, (byte) 0x03,
            (byte) 0x55, (byte) 0x04, (byte) 0x0a, (byte) 0x13, (byte) 0x12, (byte) 0x57,
            (byte) 0x57, (byte) 0x50, (byte) 0x61, (byte) 0x73, (byte) 0x73, (byte) 0x20,
            (byte) 0x43, (byte) 0x6f, (byte) 0x72, (byte) 0x70, (byte) 0x6f, (byte) 0x72,
            (byte) 0x61, (byte) 0x74, (byte) 0x69, (byte) 0x6f, (byte) 0x6e, (byte) 0x31,
            (byte) 0x2b, (byte) 0x30, (byte) 0x29, (byte) 0x06, (byte) 0x03, (byte) 0x55,
            (byte) 0x04, (byte) 0x03, (byte) 0x13, (byte) 0x22, (byte) 0x57, (byte) 0x57,
            (byte) 0x50, (byte) 0x61, (byte) 0x73, (byte) 0x73, (byte) 0x20, (byte) 0x43,
            (byte) 0x6f, (byte) 0x72, (byte) 0x70, (byte) 0x6f, (byte) 0x72, (byte) 0x61,
            (byte) 0x74, (byte) 0x69, (byte) 0x6f, (byte) 0x6e, (byte) 0x20, (byte) 0x50,
            (byte) 0x72, (byte) 0x69, (byte) 0x6d, (byte) 0x61, (byte) 0x72, (byte) 0x79,
            (byte) 0x20, (byte) 0x52, (byte) 0x6f, (byte) 0x6f, (byte) 0x74, (byte) 0x20,
            (byte) 0x43, (byte) 0x41, (byte) 0x82, (byte) 0x09, (byte) 0x00, (byte) 0xde,
            (byte) 0xc9, (byte) 0x65, (byte) 0x49, (byte) 0x60, (byte) 0x94, (byte) 0x69,
            (byte) 0xf8, (byte) 0x30, (byte) 0x0f, (byte) 0x06, (byte) 0x03, (byte) 0x55,
            (byte) 0x1d, (byte) 0x13, (byte) 0x01, (byte) 0x01, (byte) 0xff, (byte) 0x04,
            (byte) 0x05, (byte) 0x30, (byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0xff,
            (byte) 0x30, (byte) 0x0b, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1d,
            (byte) 0x0f, (byte) 0x04, (byte) 0x04, (byte) 0x03, (byte) 0x02, (byte) 0x01,
            (byte) 0x06, (byte) 0x30, (byte) 0x0d, (byte) 0x06, (byte) 0x09, (byte) 0x2a,
            (byte) 0x86, (byte) 0x48, (byte) 0x86, (byte) 0xf7, (byte) 0x0d, (byte) 0x01,
            (byte) 0x01, (byte) 0x0b, (byte) 0x05, (byte) 0x00, (byte) 0x03, (byte) 0x82,
            (byte) 0x02, (byte) 0x01, (byte) 0x00, (byte) 0x13, (byte) 0x8e, (byte) 0x82,
            (byte) 0x32, (byte) 0x29, (byte) 0x08, (byte) 0xef, (byte) 0x7e, (byte) 0xfc,
            (byte) 0x9a, (byte) 0x40, (byte) 0xb7, (byte) 0xa9, (byte) 0x9c, (byte) 0x8a,
            (byte) 0x71, (byte) 0x5c, (byte) 0x64, (byte) 0x35, (byte) 0xf2, (byte) 0xd1,
            (byte) 0x7b, (byte) 0x77, (byte) 0x83, (byte) 0xe2, (byte) 0x1d, (byte) 0x38,
            (byte) 0x38, (byte) 0xed, (byte) 0xbb, (byte) 0xae, (byte) 0x67, (byte) 0xd9,
            (byte) 0x8f, (byte) 0xf7, (byte) 0x0c, (byte) 0xac, (byte) 0x30, (byte) 0xc2,
            (byte) 0xb7, (byte) 0x40, (byte) 0x67, (byte) 0xda, (byte) 0xdf, (byte) 0x4b,
            (byte) 0x05, (byte) 0x41, (byte) 0x81, (byte) 0x75, (byte) 0x77, (byte) 0xd9,
            (byte) 0x12, (byte) 0x7d, (byte) 0x77, (byte) 0x82, (byte) 0xa9, (byte) 0xf9,
            (byte) 0xf7, (byte) 0xc1, (byte) 0x7a, (byte) 0x96, (byte) 0x62, (byte) 0xe8,
            (byte) 0x39, (byte) 0xbb, (byte) 0x4d, (byte) 0xe1, (byte) 0x06, (byte) 0x2a,
            (byte) 0x97, (byte) 0x25, (byte) 0xeb, (byte) 0x15, (byte) 0xc3, (byte) 0xf3,
            (byte) 0x16, (byte) 0x2c, (byte) 0x10, (byte) 0x6a, (byte) 0xb6, (byte) 0xda,
            (byte) 0xfb, (byte) 0x1a, (byte) 0xbc, (byte) 0xb6, (byte) 0x88, (byte) 0x31,
            (byte) 0x8c, (byte) 0xc9, (byte) 0x19, (byte) 0xdb, (byte) 0x2e, (byte) 0xf4,
            (byte) 0x32, (byte) 0x55, (byte) 0x77, (byte) 0xfc, (byte) 0xf6, (byte) 0xe4,
            (byte) 0x2a, (byte) 0x4c, (byte) 0x2f, (byte) 0xe1, (byte) 0xb0, (byte) 0x63,
            (byte) 0x39, (byte) 0xc2, (byte) 0xd9, (byte) 0x43, (byte) 0x50, (byte) 0xec,
            (byte) 0x61, (byte) 0xe8, (byte) 0x4f, (byte) 0x76, (byte) 0xca, (byte) 0xf9,
            (byte) 0xec, (byte) 0x2e, (byte) 0x88, (byte) 0x77, (byte) 0x81, (byte) 0x1e,
            (byte) 0x90, (byte) 0x44, (byte) 0x2c, (byte) 0xfd, (byte) 0xa3, (byte) 0x2d,
            (byte) 0x29, (byte) 0xc3, (byte) 0x33, (byte) 0x65, (byte) 0xa4, (byte) 0xa2,
            (byte) 0xa6, (byte) 0x44, (byte) 0xee, (byte) 0x5c, (byte) 0x5c, (byte) 0x5f,
            (byte) 0xc5, (byte) 0x6e, (byte) 0x2e, (byte) 0x06, (byte) 0x27, (byte) 0xe4,
            (byte) 0x1f, (byte) 0xef, (byte) 0xad, (byte) 0x50, (byte) 0x04, (byte) 0x83,
            (byte) 0xe3, (byte) 0x83, (byte) 0x83, (byte) 0xda, (byte) 0xbe, (byte) 0xe6,
            (byte) 0xd5, (byte) 0x49, (byte) 0x52, (byte) 0x43, (byte) 0x9b, (byte) 0xe2,
            (byte) 0x8a, (byte) 0xfd, (byte) 0xe5, (byte) 0xd2, (byte) 0xab, (byte) 0xc0,
            (byte) 0x07, (byte) 0xcf, (byte) 0x5d, (byte) 0x3e, (byte) 0x27, (byte) 0xd5,
            (byte) 0x9c, (byte) 0x87, (byte) 0x80, (byte) 0xbc, (byte) 0xf7, (byte) 0x1d,
            (byte) 0xef, (byte) 0xe1, (byte) 0x98, (byte) 0xd9, (byte) 0x15, (byte) 0xd3,
            (byte) 0x64, (byte) 0x2c, (byte) 0x37, (byte) 0xe9, (byte) 0x98, (byte) 0xa9,
            (byte) 0x9c, (byte) 0x58, (byte) 0x8e, (byte) 0x59, (byte) 0x3f, (byte) 0x53,
            (byte) 0x93, (byte) 0x24, (byte) 0xc3, (byte) 0xa4, (byte) 0x1f, (byte) 0xf0,
            (byte) 0x8d, (byte) 0x64, (byte) 0x0d, (byte) 0x16, (byte) 0xb8, (byte) 0x26,
            (byte) 0x99, (byte) 0x0b, (byte) 0xf1, (byte) 0x40, (byte) 0xb7, (byte) 0x96,
            (byte) 0x05, (byte) 0x62, (byte) 0x14, (byte) 0x49, (byte) 0xa5, (byte) 0xc9,
            (byte) 0xc2, (byte) 0x55, (byte) 0x73, (byte) 0x33, (byte) 0x3b, (byte) 0x5d,
            (byte) 0xb5, (byte) 0x38, (byte) 0x67, (byte) 0xb7, (byte) 0xf6, (byte) 0xcd,
            (byte) 0x64, (byte) 0xd1, (byte) 0x8f, (byte) 0x31, (byte) 0x17, (byte) 0xda,
            (byte) 0x67, (byte) 0xbe, (byte) 0x8e, (byte) 0x96, (byte) 0x36, (byte) 0x01,
            (byte) 0xf4, (byte) 0x12, (byte) 0x82, (byte) 0xed, (byte) 0x65, (byte) 0x26,
            (byte) 0xb2, (byte) 0xcd, (byte) 0x9f, (byte) 0xf2, (byte) 0xda, (byte) 0x07,
            (byte) 0x8b, (byte) 0x2b, (byte) 0x3e, (byte) 0x11, (byte) 0x11, (byte) 0xf3,
            (byte) 0xd3, (byte) 0x17, (byte) 0xc2, (byte) 0x4d, (byte) 0x58, (byte) 0x68,
            (byte) 0xc2, (byte) 0x5c, (byte) 0xfc, (byte) 0x5e, (byte) 0xdc, (byte) 0x16,
            (byte) 0x7d, (byte) 0xbd, (byte) 0xc0, (byte) 0xd7, (byte) 0xb8, (byte) 0xf3,
            (byte) 0x24, (byte) 0x19, (byte) 0xbe, (byte) 0x28, (byte) 0x09, (byte) 0x50,
            (byte) 0xb0, (byte) 0x73, (byte) 0xe0, (byte) 0x78, (byte) 0x11, (byte) 0x2a,
            (byte) 0xb6, (byte) 0x87, (byte) 0x31, (byte) 0xbc, (byte) 0x12, (byte) 0x5c,
            (byte) 0xaa, (byte) 0x13, (byte) 0xa2, (byte) 0x28, (byte) 0x33, (byte) 0xa9,
            (byte) 0xb0, (byte) 0xa1, (byte) 0xc7, (byte) 0xcf, (byte) 0xe9, (byte) 0xe0,
            (byte) 0x7b, (byte) 0x12, (byte) 0x0e, (byte) 0xdd, (byte) 0xe9, (byte) 0x6b,
            (byte) 0xd5, (byte) 0x30, (byte) 0x95, (byte) 0xba, (byte) 0xd3, (byte) 0xd3,
            (byte) 0x13, (byte) 0xe5, (byte) 0x1c, (byte) 0xcd, (byte) 0x84, (byte) 0xc1,
            (byte) 0x46, (byte) 0xc2, (byte) 0xfe, (byte) 0x8c, (byte) 0x87, (byte) 0x68,
            (byte) 0x23, (byte) 0x19, (byte) 0xba, (byte) 0x68, (byte) 0x0f, (byte) 0x6b,
            (byte) 0xac, (byte) 0xdd, (byte) 0xea, (byte) 0x0d, (byte) 0x5c, (byte) 0x0c,
            (byte) 0x9e, (byte) 0xe1, (byte) 0xd3, (byte) 0x85, (byte) 0x2a, (byte) 0xec,
            (byte) 0x8b, (byte) 0x0c, (byte) 0xaa, (byte) 0x39, (byte) 0x70, (byte) 0xb3,
            (byte) 0xce, (byte) 0x30, (byte) 0x9a, (byte) 0x09, (byte) 0xfe, (byte) 0x25,
            (byte) 0xe7, (byte) 0xe2, (byte) 0x86, (byte) 0xe5, (byte) 0x53, (byte) 0x62,
            (byte) 0x60, (byte) 0xfc, (byte) 0xad, (byte) 0x88, (byte) 0x68, (byte) 0x9c,
            (byte) 0xbf, (byte) 0xc3, (byte) 0xc2, (byte) 0x06, (byte) 0x3c, (byte) 0x05,
            (byte) 0x93, (byte) 0x32, (byte) 0x2b, (byte) 0xf8, (byte) 0xb4, (byte) 0x52,
            (byte) 0xc9, (byte) 0x48, (byte) 0x98, (byte) 0xcc, (byte) 0x06, (byte) 0x6e,
            (byte) 0x8b, (byte) 0x24, (byte) 0x5c, (byte) 0x86, (byte) 0x97, (byte) 0x53,
            (byte) 0xfb, (byte) 0x24, (byte) 0x40, (byte) 0x7c, (byte) 0xbe, (byte) 0xea,
            (byte) 0xa8, (byte) 0x70, (byte) 0x6e, (byte) 0x20, (byte) 0x76, (byte) 0x21,
            (byte) 0x1b, (byte) 0x71, (byte) 0x38, (byte) 0xed, (byte) 0xad, (byte) 0xc6,
            (byte) 0x82, (byte) 0xec, (byte) 0x14, (byte) 0xc1, (byte) 0x41, (byte) 0x9c,
            (byte) 0x5d, (byte) 0x1f, (byte) 0x8d, (byte) 0x8e, (byte) 0xb4, (byte) 0xa6,
            (byte) 0xb5, (byte) 0xe1, (byte) 0xd1, (byte) 0x0c, (byte) 0xe3, (byte) 0x4e,
            (byte) 0x51, (byte) 0x85, (byte) 0x02, (byte) 0x1f, (byte) 0x8d, (byte) 0x61,
            (byte) 0xc3, (byte) 0xad, (byte) 0xb8, (byte) 0xd0, (byte) 0xca, (byte) 0x35,
            (byte) 0x94, (byte) 0xbe, (byte) 0x05, (byte) 0xfa, (byte) 0xba, (byte) 0x6b,
            (byte) 0x2c, (byte) 0x40, (byte) 0x41, (byte) 0xf3, (byte) 0x89, (byte) 0x37,
            (byte) 0xfa, (byte) 0xff, (byte) 0x80, (byte) 0xb5, (byte) 0xb5, (byte) 0xde,
            (byte) 0x3c, (byte) 0x4c, (byte) 0x2f, (byte) 0xa7, (byte) 0xea, (byte) 0x35,
            (byte) 0x9e, (byte) 0xef, (byte) 0xfe, (byte) 0xd6, (byte) 0xc4, (byte) 0x64,
            (byte) 0x86, (byte) 0xa9, (byte) 0x4d, (byte) 0x14, (byte) 0x73, (byte) 0x7a,
            (byte) 0xee, (byte) 0xf6, (byte) 0xa4, (byte) 0xa8, (byte) 0x2e, (byte) 0x31,
            (byte) 0x4f, (byte) 0x18, (byte) 0xae, (byte) 0x3f, (byte) 0x1b, (byte) 0xba,
            (byte) 0x3d, (byte) 0xbf, (byte) 0xee, (byte) 0x0d, (byte) 0xe3, (byte) 0x48,
            (byte) 0x8a, (byte) 0x9d, (byte) 0x3e, (byte) 0x13, (byte) 0xd2};

    private static final class ContextHolder {
        private final byte[] hash;
        private final SSLContext context;
        private final Map<String, String> config;

        private ContextHolder(byte[] hash,
                              SSLContext context,
                              Map<String, String> config) {
            this.hash = hash;
            this.context = context;
            this.config = config;
        }
    }

    private static final class UncheckedObjectMapper {
        private final ObjectMapper mapper = new ObjectMapper();

        Map<String, String> readValue(String content) {
            try {
                return mapper.readValue(content, new TypeReference<>() {});
            } catch (JsonProcessingException e) {
                LOGGER.error("WWPass JSON processing error", e);
                return Collections.emptyMap();
            }
        }
    }

    private final KeycloakSession session;
    private static final Map<String, ContextHolder> CONTEXT_BY_CONFIG_ID = new HashMap<String, ContextHolder>();
    private static final Logger LOGGER = Logger.getLogger(WWPassConnectionProviderImpl.class);
    private static final UncheckedObjectMapper OBJECT_MAPPER = new UncheckedObjectMapper();

    public WWPassConnectionProviderImpl(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void close() {
        // Nothing to do.
    }

    private static SSLContext createSSLContext(X509Certificate certificate, PrivateKey key)
            throws GeneralSecurityException, IOException {
        KeyStore.PrivateKeyEntry pke = new KeyStore.PrivateKeyEntry(key, new Certificate[]{certificate});

        // This adds no security but Java requires to password-protect the key
        byte[] passwordBytes = new byte[16];
        (new java.security.SecureRandom()).nextBytes(passwordBytes);
        String password = Base64.encodeBytes(passwordBytes);

        KeyManagerFactory keyManagerFactory =
                KeyManagerFactory.getInstance("SunX509");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null);

        keyStore.setEntry("WWPass client key", pke,
                new KeyStore.PasswordProtection(password.toCharArray()));
        keyManagerFactory.init(keyStore, password.toCharArray());

        SSLContext context = SSLContext.getInstance("TLS");

        // Making rootCA certificate
        CertificateFactory cf;
        X509Certificate rootCA;
        try (InputStream is = new ByteArrayInputStream(WWPASS_CA_DER)) {
            cf = CertificateFactory.getInstance("X.509");
            rootCA = (X509Certificate) cf.generateCertificate(is);
        }

        // Creating TrustManager for this CA
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null);
        ks.setCertificateEntry("WWPass Root CA", rootCA);

        trustManagerFactory.init(ks);

        context.init(keyManagerFactory.getKeyManagers(),
                trustManagerFactory.getTrustManagers(),
                new java.security.SecureRandom());
        return context;
    }

    private ContextHolder getSSLContext(String configId) {
        IdentityProviderModel configModel =
                session.getContext().getRealm().getIdentityProviderByAlias(configId);
        if (configModel == null)
            throw new IllegalArgumentException("Bad Authenticator config ID: " +
                    configId);
        Map<String, String> config = configModel.getConfig();
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("Error initializing SSLContext for WWPass connection", e);
            throw new RuntimeException("Error initializing SHA-256 config: " +
                    configModel.getAlias());
        }
        for (Map.Entry<String, String> entry : config.entrySet()) {
            digest.update(entry.getKey().getBytes());
            digest.update(entry.getValue().getBytes());
        }
        byte[] configHash = digest.digest();
        ContextHolder cachedContext = CONTEXT_BY_CONFIG_ID.get(configId);

        if (cachedContext != null &&
                Arrays.equals(configHash, cachedContext.hash))
            return cachedContext;

        String certText = config.get("certificate");
        String keyText = config.get("privateKey");
        if (certText == null || certText.isEmpty() || keyText == null || keyText.isEmpty())
            throw new IllegalArgumentException(
                    "WWPass Authentication requires private key and certificate for config: " +
                            configModel.getAlias());
        try {
            X509Certificate certificate = PemUtils.decodeCertificate(certText);
            PrivateKey privateKey = PemUtils.decodePrivateKey(keyText);
            SSLContext sslContext = createSSLContext(certificate, privateKey);
            ContextHolder newContext =
                    new ContextHolder(configHash, sslContext, config);
            CONTEXT_BY_CONFIG_ID.put(configId, newContext);
            return newContext;
        } catch (IOException | GeneralSecurityException e) {
            LOGGER.error("Error initializing SSLContext for WWPass connection", e);
            throw new IllegalArgumentException(
                    "Error initializing SSLContext for WWPass connection for config: " +
                            configModel.getAlias());
        }
    }

    private static Map<String, String> jsonRequest(SSLContext sslContext, URI uri) {
        HttpRequest request = HttpRequest.newBuilder(uri)
                .header("Accept", "application/json")
                .build();
        HttpClient client = HttpClient.newBuilder()
                .sslContext(sslContext)
                .build();
        try {
            return OBJECT_MAPPER.readValue(client.send(request, BodyHandlers.ofString()).body());
        } catch (IOException | InterruptedException e) {
            LOGGER.error("Error accessing WWPass");
            return Collections.emptyMap();
        }
    }

    private static Map<String, String> request(ContextHolder ctx, String command,
                                               String... params) {
        KeycloakUriBuilder uriBuilder = (new KeycloakUriBuilder());
        uriBuilder.scheme("https")
                .host("spfe.wwpass.com")
                .path(String.format("/%s.json", command));
        for (int i = 0; i < params.length; i += 2) {
            uriBuilder.queryParam(params[i], params[i + 1]);
        }
        Map<String, String> result = jsonRequest(ctx.context, uriBuilder.build());
        if (result == null) {
            throw new IllegalStateException("WWPass result is null");
        }
        LOGGER.infov("WWPass reply: {0}", result);
        if (!Objects.equals(result.get("result"), "true")) {
            LOGGER.errorv("WWPass error: {0}", result.toString());
            throw new RuntimeException(String.format("WWPass error: %s", result.get("data")));
        }
        return result;
    }

    @Override
    public WWPassTicket getTicket(String configId) {
        ContextHolder context = getSSLContext(configId);
        Map<String, String> result = request(
                context, "get", "auth_type",
                context.config.get("usePIN").equals("true") ? "p" : "");
        return new WWPassTicket(result.get("data"),
                Integer.parseInt(result.get("ttl")));
    }

    @Override
    public String getPUID(String configId, String ticket) {
        ContextHolder context = getSSLContext(configId);
        Map<String, String> result = request(
                context, "puid", "ticket", ticket, "auth_type",
                context.config.get("usePIN").equals("true") ? "p" : "");
        return result.get("data");
    }
}
