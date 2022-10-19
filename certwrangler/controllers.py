import logging
import time
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import josepy as jose

from acme import challenges as acme_challenges
from acme import client as acme_client
from acme import errors as acme_errors
from acme import jws as acme_jws
from acme import messages as acme_messages

from certwrangler.dns import resolve_cname, resolve_zone
from certwrangler.exceptions import ControllerError
from certwrangler.models import Account, AccountState, Cert, CertState

USER_AGENT = "certwrangler"
log = logging.getLogger(__name__)


class AccountKeyChangeMessage(acme_messages.ResourceBody):
    """Account Key change message since the acme client doesn't seem to have this."""

    oldKey: jose.JWK = jose.field("oldKey", decoder=jose.JWK.from_json)
    account: str = jose.field("account")


def _get_acme_client(account: Account) -> acme_client.ClientV2:
    net = acme_client.ClientNetwork(
        account.state.key, account=account.state.registration, user_agent=USER_AGENT
    )
    directory = acme_messages.Directory.from_json(net.get(account.server).json())
    return acme_client.ClientV2(directory, net=net)


class AccountController:
    """
    Controller for ACME account operations.
    """

    def __init__(self, account: Account) -> None:
        self.account = account
        # Load to ensure we have the update state from the store.
        self.account.load()
        self._client = None

    @property
    def client(self) -> acme_client.ClientV2:
        # Lazy load this so we don't make API calls when no work needs to happen.
        if not self._client:
            self._client = _get_acme_client(self.account)
        return self._client

    def create_key(self) -> None:
        """
        Create a new key and reset the account state.
        """

        new_key = jose.JWKRSA(
            key=rsa.generate_private_key(
                public_exponent=65537, key_size=self.account.key_size
            )
        )
        self.account.state = AccountState(key=new_key, key_size=self.account.key_size)
        self.account.save()
        self._client = _get_acme_client(self.account)

    def register(self) -> None:
        """
        Register a new account.
        """

        try:
            self.account.state.registration = self.client.new_account(
                acme_messages.NewRegistration.from_data(
                    email=",".join(self.account.emails), terms_of_service_agreed=True
                )
            )
            self.client.net.account = self.account.state.registration
            self.account.save()
        except acme_errors.ConflictError:
            # Account already exists, so recover instead.
            log.info(
                f"Registration exists for account '{self.account.name}', recovering..."
            )
            self.get_registration()

    def get_registration(self) -> None:
        """
        Get registration for an existing account.
        """

        self.account.state.registration = self.client.query_registration(
            acme_messages.RegistrationResource.from_json({"body": {}, "uri": None})
        )
        self.client.net.account = self.account.state.registration
        self.account.save()

    def change_key(self) -> None:
        """
        Change the account key.
        """

        new_private_key = jose.JWKRSA(
            key=rsa.generate_private_key(
                public_exponent=65537, key_size=self.account.key_size
            )
        )

        # The certbot ACME library doesn't implement this call so we have to craft
        # it ourselves. The operation is described in RFC 8555 section 7.3.5:
        # https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.5
        # The TL;DR is that we have an inner message containing the old public key and
        # account uri that's signed by the new key, encapsulated by an outer
        # message signed by the old key, showing that the holder(s) of both keys
        # consent to the change.

        inner_message = acme_jws.JWS.sign(
            AccountKeyChangeMessage.from_json(
                {
                    "account": self.account.state.registration.uri,
                    "oldKey": self.account.state.registration.body.key.to_json(),
                }
            )
            .json_dumps()
            .encode(),
            new_private_key,
            jose.RS256,
            None,
            url=self.client.directory["keyChange"],
            kid=None,
        )

        # The _post() method signs with the old key, completing the message.
        response = self.client._post(self.client.directory["keyChange"], inner_message)
        if response.status_code != 200:
            raise ControllerError(response.reason)
        # Now we reset our state with the new key.
        self.account.state = AccountState(
            key=new_private_key, key_size=self.account.key_size
        )
        self.account.save()
        # Get a new client since the key changed.
        self._client = _get_acme_client(self.account)
        # Then get our new registration
        self.get_registration()

    def update_contacts(self) -> None:
        """
        Update the contact information on the account.
        """
        emails = tuple(
            (
                f"{self.account.state.registration.body.email_prefix}{email}"
                for email in self.account.emails
            )
        )
        self.account.state.registration = self.client.update_registration(
            self.account.state.registration.update(
                body=self.account.state.registration.body.update(contact=emails)
            )
        )
        self.account.save()


class CertController:
    """
    Controller for ACME cert operations.
    """

    def __init__(self, cert: Cert) -> None:
        self.cert = cert
        # Load to ensure we have the update state from the store.
        self.cert.load()
        self._client = None
        self._dns_records = None

    @property
    def client(self) -> acme_client.ClientV2:
        # Lazy load this so we don't make API calls when no work needs to happen.
        if not self._client:
            self._client = _get_acme_client(self.cert.account)
        return self._client

    def create_key(self) -> None:
        """
        Create a new key and reset the cert state.
        """

        new_key = rsa.generate_private_key(
            public_exponent=65537, key_size=self.cert.key_size
        )
        self.cert.state = CertState(key=new_key, key_size=self.cert.key_size)
        self.cert.save()

    def create_order(self) -> None:
        self.cert.state.csr = self._create_csr()
        self.cert.state.order = self.client.new_order(
            self.cert.state.csr.public_bytes(serialization.Encoding.PEM)
        )
        self.cert.save()
        self.process_order()

    def process_order(self) -> None:
        # First get an update response from the ACME server
        self._update_order()
        order = self.cert.state.order
        if order.body.status == acme_messages.STATUS_PENDING:
            # Do the challenges
            try:
                self.process_challenges()
                self.finalize_order()
            # TODO: this shouldn't fail the order on validation error
            # we should instead be retrying.
            except (ValueError, acme_errors.ValidationError) as error:
                # Something broke, fail the order
                self._fail_order(error)
                return
            self.clean_up()
            return
        elif order.body.status in [
            acme_messages.STATUS_READY,
            acme_messages.STATUS_PROCESSING,
        ]:
            try:
                self.finalize_order()
            except (ValueError, acme_errors.ValidationError) as error:
                # Something broke, fail the order
                self._fail_order(error)
                return
            self.clean_up()
            return
        elif order.body.status == acme_messages.STATUS_VALID:
            certificate_response = self.client._post_as_get(order.body.certificate)
            self.cert.state.cert = x509.load_pem_x509_certificate(
                certificate_response.text.encode()
            )
            self.cert.save()
            self.clean_up()
            return
        elif order.body.status == acme_messages.STATUS_INVALID:
            # Order is invalid, kill it
            return self._fail_order(order.body.error)
        else:
            return self._fail_order(f"Unknown order status '{order.body.status.name}'")

    def process_challenges(self) -> None:

        challenges = self._get_challenges()
        # Create the TXT records
        for name, zone, token in self._get_dns_records():
            self.cert.solver.create(name, zone, token)
        # TODO: do something better than a sleep here
        log.info(
            f"DNS records created for cert '{self.cert.name}', sleeping {self.cert.wait_time} seconds..."
        )
        time.sleep(self.cert.wait_time)
        log.info(f"Submitting challenges for validation for cert '{self.cert.name}'...")
        for _, challenge in challenges:
            self.client.answer_challenge(
                challenge, challenge.response(self.cert.account.state.key)
            )

    def finalize_order(self) -> None:
        self.cert.state.order = self.client.poll_and_finalize(self.cert.state.order)
        self.cert.state.cert = x509.load_pem_x509_certificate(
            self.cert.state.order.fullchain_pem.encode()
        )
        self.cert.state.url = self.cert.state.order.body.certificate
        self.cert.save()
        self.cert.publish()
        log.info(f"Order complete for cert '{self.cert.name}'.")

    def clean_up(self) -> None:
        for name, zone, token in self._get_dns_records(completed=True):
            self.cert.solver.delete(name, zone, token)
        self.cert.state.order = None
        self.cert.save()

    def _create_csr(self) -> bytes:
        domains = []
        for domain in [self.cert.common_name] + self.cert.alt_names:
            domains.append(x509.DNSName(domain))
        subjects = [x509.NameAttribute(NameOID.COMMON_NAME, self.cert.common_name)]
        for subject in [
            self.cert.subject.country,
            self.cert.subject.state_or_province,
            self.cert.subject.locality,
            self.cert.subject.organization,
            self.cert.subject.organizational_unit,
        ]:
            if subject:
                subjects.append(subject)
        return (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name(subjects))
            .add_extension(
                x509.SubjectAlternativeName(domains),
                critical=False,
            )
            .sign(self.cert.state.key, hashes.SHA256())
        )

    def _update_order(self) -> None:
        """
        Update the order status from the server in case it changed.
        """
        order_uri = self.cert.state.order.uri
        csr_pem = self.cert.state.order.csr_pem
        response = self.client._post_as_get(order_uri)
        body = acme_messages.Order.from_json(response.json())
        authorizations = []
        for uri in body.authorizations:
            authorizations.append(
                self.client._authzr_from_response(
                    self.client._post_as_get(uri), uri=uri
                )
            )
        self.cert.state.order = acme_messages.OrderResource(
            body=body,
            uri=order_uri,
            authorizations=authorizations,
            csr_pem=csr_pem,
        )
        self.cert.save()

    def _get_challenges(
        self, completed: bool = False
    ) -> list[tuple[str, acme_messages.ChallengeBody]]:
        # First check for any errors
        errors = []
        for authz in self.cert.state.order.authorizations:
            if authz.body.status in [
                acme_messages.STATUS_DEACTIVATED,
                acme_messages.STATUS_REVOKED,
                acme_messages.STATUS_UNKNOWN,
            ]:
                errors.append(authz)
        if errors:
            raise acme_errors.ValidationError(errors)
        challenges = []
        # Now find the challenges
        for authz in self.cert.state.order.authorizations:
            domain = authz.body.identifier.value
            status = authz.body.status
            if completed or status in [
                acme_messages.STATUS_PENDING,
                acme_messages.STATUS_PROCESSING,
            ]:
                for challenge in authz.body.challenges:
                    if isinstance(challenge.chall, acme_challenges.DNS01):
                        challenges.append((domain, challenge))
        return challenges

    def _get_dns_records(self, completed: bool = False) -> list[tuple[str, str, str]]:
        dns_records = []
        challenges = self._get_challenges(completed)
        for domain, challenge in challenges:
            challenge_name = f"_acme-challenge.{domain}"
            if self.cert.follow_cnames:
                challenge_name = resolve_cname(challenge_name)
            zone = resolve_zone(challenge_name)
            name = ".".join(challenge_name.split(".")[: -len(zone.split("."))])
            token = challenge.validation(self.cert.account.state.key)
            dns_records.append((name, zone, token))
        return dns_records

    def _fail_order(self, error: Exception = None) -> None:
        # Trash the order and try again on the next loop
        error_msg = f"Removing invalid order for cert '{self.cert.name}'."
        if error:
            error_msg = f"{error_msg} Error: {error}"
        log.warning(error_msg)
        self.clean_up()
        return
