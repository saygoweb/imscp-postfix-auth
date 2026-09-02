#!/usr/bin/env python3
"""Submit one message over SMTP, for test/dkim-matrix.sh.

Kept out of the shell script because what these tests turn on is the exact
shape of the submission - which port, from which address, authenticated or
not - and that is unreadable through several layers of shell quoting.

  smtp-send.py <host> <port> <envelope-from> <rcpt> <subject> [user] [password]

Exits 0 if the message was accepted, 1 otherwise, printing the reason.
"""

import smtplib
import ssl
import sys


def main():
    if len(sys.argv) < 6:
        print(__doc__)
        return 2

    host, port, sender, rcpt, subject = sys.argv[1:6]
    user = sys.argv[6] if len(sys.argv) > 6 else None
    password = sys.argv[7] if len(sys.argv) > 7 else None

    message = (
        "From: {sender}\r\n"
        "To: {rcpt}\r\n"
        "Subject: {subject}\r\n"
        "\r\n"
        "Sent by the SGW_PostfixAuth test suite.\r\n"
    ).format(sender=sender, rcpt=rcpt, subject=subject)

    try:
        server = smtplib.SMTP(host, int(port), timeout=30)
        server.ehlo()

        if user:
            # The submission port offers STARTTLS with i-MSCP's self-signed
            # certificate, so verification is deliberately off: what is under
            # test is the signing decision, not the certificate.
            context = ssl._create_unverified_context()
            server.starttls(context=context)
            server.ehlo()
            server.login(user, password)

        server.sendmail(sender, [rcpt], message)
        server.quit()
    except Exception as exc:
        print("{0}: {1}".format(type(exc).__name__, exc))
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
