x509:
  lookup:
    pkgs:
      - openssl
      - gnutls
      - ca-certificates
  defaults:
    base_certificate:
      C: AU
      ST: Queensland
      L: Brisbane
      O: Example Org Pty Ltd
      OU: SecDevMonkeyOps
      Email: secdevmonkeyops@example.org
      basicConstraints: 'critical CA:false'
      keyUsage: 'digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement'
      subjectKeyIdentifier: 'hash'
      authorityKeyIdentifier: 'keyid,issuer:always'
      days_valid: 500
    ca_certificate:
      basicConstraints: 'critical CA:true'
      keyUsage: 'critical digitalSignature, cRLSign, keyCertSign'
      days_valid: 2000
  revoked_attributes:
    - certificate
    - serial_number
    - not_after
    - revocation_date
    - reason
  minion:
    remove:
      - /etc/pki/blah/file.crt
      - /etc/pki/blah/file.key
    static:
      certificates:
        name:
          content: |
            blah
        other_name:
          source: salt://x509/files/blah.crt
      keys:
        name:
          content: |
            blah
        other_name:
          source: salt://x509/files/blah.key
      trust_anchors:
        name:
          content: |
            blah
        other_name:
          source: salt://x509/files/blah.crt
      chains:
        name:
          content: |
            blah
        other:
          files:
            - /path/to/file1
            - /path/to/file2
    generate:
      asdf:
        create_key: True
        attributes:
          blah: blah
      xyz:
        create_key: False
        attributes:
          blah: blah
  ca:
    static:
      certificates:
        name:
          content: |
            blah
      keys:
        name:
          file: salt://x509/files/name.key
    signing_policies:
      source: salt://files/x509/ca/signing_policies.conf
    generate:
      org_root_ca:
        CN: "Some Org Root CA"
        crlDistributionPoints: URI:http://some.org/crl/root.crl
        sub:
          org_a1_ca:
            CN: "Some Org A1 CA"
            crlDistributionPoints: URI:http://some.org/crl/a1.crl
            sub:
              org_user_ca:
                CN: "Some Org A1 User CA"
                crlDistributionPoints: URI:http://some.org/crl/a1_user.crl
                create:
                  test_user1:
                    attributes:
                      CN: "Monkey Magic"
                      GN: "Monkey"
                      SN: "Magic"
                      extendedKeyUsage: clientAuth
                      nsCertType: client
                      days_valid: 10000
                  test_user2:
                    attributes:
                      CN: "Trippi Tarka"
                      GN: "Trippi"
                      SN: "Tarka"
                      extendedKeyUsage: clientAuth
                      nsCertType: client
                      days_valid: 10000
              org_server_ca:
                CN: "Some Org A1 Server CA"
                crlDistributionPoints: URI:http://some.org/crl/a1_server.crl
                create:
                  test_server:
                    attributes:
                      CN: "Test Server"
                      extendedKeyUsage: serverAuth, clientAuth
                      subjectAltName: DNS:localhost.localdomain IP:127.0.0.1
                      nsComment: blah
                      nsCertType: server
                      days_valid: 10000
                      version: 10
                      serial_bits: 128
                      algorithm: sha512
                      backup: True
              org_device_ca:
                CN: "Some Org A1 Device CA"
                crlDistributionPoints: URI:http://some.org/crl/a1_device.crl
                create:
                  test_device:
                    CN: "Test Device"
                revoked:
                  dead_device:
                    serial_number: D6:D2:DC:D8:4D:5C:C0:F4
                    not_after: "\"2025-01-01 00:00:00\""
                    revocation_date: "\"2015-02-25 00:00:00\""
                    reason: cessationOfOperation
